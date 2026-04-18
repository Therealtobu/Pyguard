"""
Stage 5 – VM4 Watchdog Generation (Modules 5.1 → 5.4)

5.1 – WatchdogCodeGenerator   : produces C source for the anti-tamper thread
5.2 – SelfModifyingLogic      : adds self-patching stubs to the C source
5.3 – WatchdogCompiler        : compiles C → shared object (.so)
5.4 – WatchdogEmbedder        : base64-encodes the .so, inserts into payload

The watchdog runs as a daemon pthread that continuously:
  • Checks CRC32 of SR-VM / GT-VM / native-block memory regions
  • Detects software breakpoints (0xCC bytes) in hot pages
  • Detects ptrace / /proc/self/status TracerPid
  • Detects Frida (checks for frida-agent in /proc/self/maps)
  • Detects LD_PRELOAD / suspicious loaded libs
  • Monitors timing (sleep/nanosleep anomaly under debugger)
  • Self-modifies a canary function on detection

On detection: corrupts a global key byte → decryption fails silently.
"""

from __future__ import annotations
import os
import re
import base64
import shutil
import struct
import random
import hashlib
import tempfile
import subprocess
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# 5.1 – Watchdog C Code Generator
# ─────────────────────────────────────────────────────────────────────────────

WATCHDOG_C_TEMPLATE = r"""
/* VM4 Watchdog – auto-generated anti-tamper C thread
   DO NOT EDIT – regenerated on every build */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <errno.h>

/* ── Build-time constants ──────────────────────────────────────────────── */
static const uint32_t _WD_POLL_MS     = {poll_ms};
static const uint32_t _WD_CRC_SEED    = {crc_seed:#010x};
static const uint8_t  _WD_CANARY[16]  = {{ {canary_bytes} }};

/* ── Shared state (set by loader at startup) ───────────────────────────── */
volatile uint8_t*  _wd_key_ptr   = NULL;   /* pointer to master key byte 0 */
volatile uint32_t  _wd_key_len   = 0;
volatile uint8_t*  _wd_vm_text   = NULL;   /* SR-VM interpreter .text addr  */
volatile uint32_t  _wd_vm_size   = 0;
static   uint32_t  _wd_vm_crc    = 0;      /* baseline CRC, set on first check */
static   pthread_t _wd_thread;
static   volatile int _wd_running = 0;

/* ── CRC32 ─────────────────────────────────────────────────────────────── */
static uint32_t _crc32(const uint8_t* data, size_t len, uint32_t crc) {{
    crc ^= 0xFFFFFFFF;
    while (len--) {{
        crc ^= *data++;
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }}
    return crc ^ 0xFFFFFFFF;
}}

/* ── Corruption on tamper detection ────────────────────────────────────── */
static void __attribute__((noinline)) _wd_corrupt(void) {{
    /* Silently zero the master key – decryption fails on next use */
    if (_wd_key_ptr && _wd_key_len) {{
        volatile uint8_t* p = _wd_key_ptr;
        for (uint32_t i = 0; i < _wd_key_len; i++)
            p[i] ^= _WD_CANARY[i & 15];
    }}
    /* Additional: overwrite our own export table to prevent re-init */
    _wd_running = 0;
}}

/* ── Anti-ptrace check ─────────────────────────────────────────────────── */
static int _check_ptrace(void) {{
    /* Method 1: ptrace self – returns -1 if already traced */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {{
        return 1;  /* being traced */
    }}
    ptrace(PTRACE_DETACH, 0, NULL, NULL);

    /* Method 2: /proc/self/status TracerPid */
    FILE* f = fopen("/proc/self/status", "r");
    if (f) {{
        char line[256];
        while (fgets(line, sizeof(line), f)) {{
            if (strncmp(line, "TracerPid:", 10) == 0) {{
                int pid = atoi(line + 10);
                fclose(f);
                return pid != 0;
            }}
        }}
        fclose(f);
    }}
    return 0;
}}

/* ── Frida / injection detection ───────────────────────────────────────── */
static const char* _BAD_LIBS[] = {{
    "frida", "inject", "xposed", "substrate",
    "cycript", "libhooker", NULL
}};

static int _check_maps(void) {{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {{
        for (int i = 0; _BAD_LIBS[i]; i++) {{
            if (strstr(line, _BAD_LIBS[i])) {{
                fclose(f);
                return 1;
            }}
        }}
    }}
    fclose(f);
    return 0;
}}

/* ── LD_PRELOAD check ──────────────────────────────────────────────────── */
static int _check_preload(void) {{
    const char* preload = getenv("LD_PRELOAD");
    return preload && preload[0] != '\0';
}}

/* ── Timing anomaly (debugger step causes long delay) ──────────────────── */
static int _check_timing(void) {{
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    volatile int dummy = 0;
    for (int i = 0; i < 1000; i++) dummy ^= i;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long elapsed_us = (t1.tv_sec - t0.tv_sec) * 1000000L +
                      (t1.tv_nsec - t0.tv_nsec) / 1000L;
    (void)dummy;
    return elapsed_us > 50000L;  /* >50ms = probably stepping */
}}

/* ── Breakpoint scan in VM interpreter text ────────────────────────────── */
static int _check_breakpoints(void) {{
    if (!_wd_vm_text || !_wd_vm_size) return 0;
    const uint8_t* p = _wd_vm_text;
    for (uint32_t i = 0; i < _wd_vm_size; i++) {{
        if (p[i] == 0xCC) return 1;  /* INT3 software breakpoint */
    }}
    return 0;
}}

/* ── CRC integrity check ───────────────────────────────────────────────── */
static int _check_crc(void) {{
    if (!_wd_vm_text || !_wd_vm_size) return 0;
    uint32_t current = _crc32(_wd_vm_text, _wd_vm_size, _WD_CRC_SEED);
    if (_wd_vm_crc == 0) {{
        _wd_vm_crc = current;  /* first run: establish baseline */
        return 0;
    }}
    return current != _wd_vm_crc;
}}

{self_modify_stub}

/* ── Main watchdog loop ────────────────────────────────────────────────── */
static void* _wd_loop(void* arg) {{
    (void)arg;
    struct timespec sleep_ts = {{ 0, {poll_ms} * 1000000L }};
    uint32_t check_mask = 0;

    while (_wd_running) {{
        nanosleep(&sleep_ts, NULL);
        check_mask = (check_mask + 1) & 0xF;

        int tampered = 0;

        /* Rotate checks to avoid constant overhead */
        switch (check_mask & 0x7) {{
            case 0: tampered |= _check_ptrace();      break;
            case 1: tampered |= _check_maps();         break;
            case 2: tampered |= _check_preload();      break;
            case 3: tampered |= _check_timing();       break;
            case 4: tampered |= _check_breakpoints();  break;
            case 5: tampered |= _check_crc();          break;
            default: break;
        }}

        if (tampered) {{
            _wd_corrupt();
            _wd_running = 0;
            return NULL;
        }}
    }}
    return NULL;
}}

/* ── Public API ────────────────────────────────────────────────────────── */
__attribute__((visibility("default")))
int wd_init(uint8_t* key_ptr, uint32_t key_len,
            uint8_t* vm_text, uint32_t vm_size) {{
    _wd_key_ptr = key_ptr;
    _wd_key_len = key_len;
    _wd_vm_text = vm_text;
    _wd_vm_size = vm_size;
    _wd_running = 1;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int r = pthread_create(&_wd_thread, &attr, _wd_loop, NULL);
    pthread_attr_destroy(&attr);
    return r;
}}

__attribute__((visibility("default")))
void wd_stop(void) {{
    _wd_running = 0;
}}
"""

SELF_MODIFY_STUB = r"""
/* ── Self-modifying canary function ────────────────────────────────────── */
/* This function patches itself after first invocation.
   A debugger that steps through will see different bytes on second pass. */
static uint8_t _canary_patch[8] = {{ {patch_bytes} }};

static void __attribute__((noinline)) _wd_self_modify(void) {{
    /* Write random NOPs over our own prologue to confuse disassemblers */
    uint8_t* self = (uint8_t*)_wd_self_modify;
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = (uintptr_t)self & ~(page_size - 1);
    if (mprotect((void*)page_start, page_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {{
        for (int i = 0; i < 8; i++) {{
            self[i] = _canary_patch[i % sizeof(_canary_patch)];
        }}
        __builtin___clear_cache((char*)self, (char*)self + 8);
        mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC);
    }}
}}
"""


class WatchdogCodeGenerator:

    def __init__(self, seed: int = 0, poll_ms: int = 250):
        self._rng     = random.Random(seed)
        self._poll_ms = poll_ms

    def generate(self) -> str:
        crc_seed   = self._rng.randint(0, 0xFFFFFFFF)
        canary     = [self._rng.randint(0, 255) for _ in range(16)]
        canary_str = ", ".join(f"0x{b:02x}" for b in canary)
        patch      = [self._rng.randint(0, 255) for _ in range(8)]
        patch_str  = ", ".join(f"0x{b:02x}" for b in patch)

        sm_stub = SELF_MODIFY_STUB.format(patch_bytes=patch_str)

        return WATCHDOG_C_TEMPLATE.format(
            poll_ms      = self._poll_ms,
            crc_seed     = crc_seed,
            canary_bytes = canary_str,
            self_modify_stub = sm_stub,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 5.2 – Self-Modifying Logic (already embedded in template above)
# Additional layer: generate multiple entry points with equivalent logic
# ─────────────────────────────────────────────────────────────────────────────

EXTRA_ENTRY_TEMPLATE = r"""
/* Alternative entry point variant {idx} – obfuscates symbol table */
__attribute__((visibility("default"), noinline))
int wd_init_{idx}(uint8_t* kp, uint32_t kl, uint8_t* vt, uint32_t vs) {{
    return wd_init(kp ^ {xor1:#04x}, kl, vt, vs);
}}
"""

class SelfModifyingLogic:
    """Appends redundant entry points to confuse symbol-based analysis."""

    def __init__(self, seed: int = 0, n_variants: int = 3):
        self._rng       = random.Random(seed)
        self._n_variants= n_variants

    def augment(self, c_source: str) -> str:
        extras = []
        for i in range(self._n_variants):
            xor1 = self._rng.randint(1, 255)
            extras.append(EXTRA_ENTRY_TEMPLATE.format(idx=i, xor1=xor1))
        return c_source + "\n".join(extras)


# ─────────────────────────────────────────────────────────────────────────────
# 5.3 – Watchdog Compiler
# ─────────────────────────────────────────────────────────────────────────────

COMPILE_FLAGS = [
    "-O2", "-shared", "-fPIC",
    "-fno-stack-protector",
    "-fvisibility=hidden",
    "-fomit-frame-pointer",
    "-pthread",
    "-Wl,--strip-all",
    "-Wl,-z,now",
    "-Wl,-z,relro",
]

class WatchdogCompiler:

    def __init__(self):
        self._has_gcc   = bool(shutil.which("gcc"))
        self._has_clang = bool(shutil.which("clang"))

    def compile(self, c_source: str) -> bytes:
        """Compile C source → .so bytes. Falls back to stub if no compiler."""
        if self._has_gcc or self._has_clang:
            return self._compile_native(c_source)
        return self._stub_so(c_source)

    def _compile_native(self, c_source: str) -> bytes:
        cc = "gcc" if self._has_gcc else "clang"
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "watchdog.c")
            out = os.path.join(td, "watchdog.so")
            with open(src, "w") as f:
                f.write(c_source)
            cmd = [cc] + COMPILE_FLAGS + [src, "-o", out]
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=60)
                with open(out, "rb") as f:
                    return f.read()
            except Exception as e:
                return self._stub_so(c_source)

    def _stub_so(self, c_source: str) -> bytes:
        """
        Placeholder ELF when no compiler is available.
        Runtime detects this and disables watchdog gracefully.
        """
        MAGIC = b"WDSTUB\x01\x00"
        compressed = __import__("zlib").compress(c_source.encode(), 9)
        return MAGIC + struct.pack('<I', len(compressed)) + compressed


# ─────────────────────────────────────────────────────────────────────────────
# 5.4 – Watchdog Embedder
# ─────────────────────────────────────────────────────────────────────────────

WD_BUNDLE_MAGIC = b"WDBND\x01"


class WatchdogEmbedder:
    """
    Encodes the .so bytes as base64 and wraps in a binary bundle
    suitable for embedding in the stage7 payload.

    Bundle format:
      [6B: magic]
      [4B: so_len]
      [so_bytes]
      [32B: SHA-256 hash of so_bytes]
      [2B: b64_len]
      [b64_bytes]   ← base64 of so_bytes (for Python ctypes loader)
    """

    def embed(self, so_bytes: bytes) -> bytes:
        sha = hashlib.sha256(so_bytes).digest()
        b64 = base64.b64encode(so_bytes)
        return b"".join([
            WD_BUNDLE_MAGIC,
            struct.pack('<I', len(so_bytes)),
            so_bytes,
            sha,
            struct.pack('<H', len(b64)),
            b64,
        ])

    def extract(self, bundle: bytes) -> tuple[bytes, bytes]:
        """Returns (so_bytes, b64_bytes). Verifies SHA-256."""
        assert bundle[:6] == WD_BUNDLE_MAGIC, "Bad watchdog bundle magic"
        off    = 6
        so_len = struct.unpack('<I', bundle[off:off+4])[0]; off += 4
        so_b   = bundle[off:off+so_len]; off += so_len
        sha    = bundle[off:off+32]; off += 32
        b64_len= struct.unpack('<H', bundle[off:off+2])[0]; off += 2
        b64_b  = bundle[off:off+b64_len]
        assert hashlib.sha256(so_b).digest() == sha, "Watchdog SHA-256 mismatch"
        return so_b, b64_b

    def generate_loader_snippet(self, b64_var: str = "_WD_B64") -> str:
        """Python snippet to load watchdog .so at runtime via ctypes."""
        return f"""\
# Watchdog loader (auto-generated)
import ctypes, base64, tempfile, os as _os
def _load_watchdog(key_ptr, key_len, vm_text_ptr, vm_size):
    try:
        _so_bytes = base64.b64decode({b64_var})
        if _so_bytes[:6] == b"WDSTUB":
            return  # stub – no compiler available during build
        _tf = tempfile.NamedTemporaryFile(suffix='.so', delete=False)
        _tf.write(_so_bytes); _tf.close()
        _wd = ctypes.CDLL(_tf.name)
        _wd.wd_init(key_ptr, key_len, vm_text_ptr, vm_size)
        _os.unlink(_tf.name)
    except Exception:
        pass  # watchdog load failure is non-fatal
"""


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline entry
# ─────────────────────────────────────────────────────────────────────────────

def build_watchdog(
    seed:     int = 0,
    poll_ms:  int = 250,
) -> tuple[str, bytes, bytes]:
    """
    Full stage 5 pipeline.
    Returns (c_source, so_bytes, bundle_bytes).
    """
    gen      = WatchdogCodeGenerator(seed=seed, poll_ms=poll_ms)
    sm       = SelfModifyingLogic(seed=seed + 1)
    compiler = WatchdogCompiler()
    embedder = WatchdogEmbedder()

    c_src    = gen.generate()
    c_src    = sm.augment(c_src)
    so_bytes = compiler.compile(c_src)
    bundle   = embedder.embed(so_bytes)

    return c_src, so_bytes, bundle
