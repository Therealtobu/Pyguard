"""
Module 7.6 – Python Stub Generator (v3 — Modules A–H)

Produces the final obfuscated_final.py that:
  1.  Watermark "Protected by Pyguard V1" + file integrity check
  2.  Module A – Anti-Trace   : timing, frame scan, code hash, threading, mutations
  3.  Module B – Anti-Replay  : polymorphic canary, self-destruct, fingerprint
  4.  Module C – Anti-Debug   : modules BL, TracerPid, ptrace, SIGTRAP, env, threads
  5.  Module D – Anti-Dump    : secret split + mprotect + decoy flood
  6.  Module E – Anti-VM      : QEMU/KVM, Docker/LXC, Android emulator, WSL
  7.  Module F – Anti-Hook    : 18-point hook scan, frida, trampolines, crypto integrity
  8.  Module G – SO Integrity : ELF magic, size, SHA-256, breakpoints, sections, phdr
  9.  Module H – Heartbeat    : background daemon thread, late-attach detection
  10. Decrypts + loads the C extension from embedded base64 blob
  11. Decrypts payload and passes it to C extension

Detection response (Modules A/B/C/D/E/F/G):
  • Print "Stop hooking and editing the script."
  • Plant polymorphic canary file (caught on next run)
  • Silent self-destruct (overwrite __file__ with junk)
  • Hard exit via os.abort()

Module F (_pg_anti_hook) calls _hk_die() directly for zero-latency response.
Module H (heartbeat) calls _hb_terminate() silently (no print).
"""
from __future__ import annotations
import hashlib
import textwrap

from stage7.anti_trace    import generate_anti_trace_code, finalise_code_hash
from stage7.anti_replay   import generate_anti_replay_code
from stage7.anti_debug_v2 import generate_anti_debug_code
from stage7.anti_dump     import generate_anti_dump_code
from stage7.anti_vm       import generate_anti_vm_code
from stage7.anti_hook     import generate_anti_hook_code
from stage7.so_integrity  import generate_so_integrity_code, compute_so_sha256
from stage7.heartbeat     import generate_heartbeat_code


# ─────────────────────────────────────────────────────────────────────────────
# Build-time helpers
# ─────────────────────────────────────────────────────────────────────────────

WATERMARK = "Protected by Pyguard V1"
_WATERMARK_HASH = hashlib.sha256(WATERMARK.encode()).hexdigest()


def _compute_stub_integrity_hash(stub_body: str) -> str:
    lines = [
        l for l in stub_body.splitlines()
        if not l.strip().startswith("_PG_IHASH")
    ]
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def finalise_integrity_hash(obf_source: str) -> str:
    """
    Replace the integrity-hash placeholder with the real SHA-256 of the
    final source (excluding the _PG_IHASH line itself).
    Call AFTER final_obfuscate() so the hash covers the actual on-disk form.
    """
    real_hash = _compute_stub_integrity_hash(obf_source)
    return obf_source.replace(
        repr("__PG_IHASH_PLACEHOLDER__"),
        repr(real_hash),
        1,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Stub template
# ─────────────────────────────────────────────────────────────────────────────

_STUB_TEMPLATE = '''\
# Protected by Pyguard V1
# ─────────────────────────────────────────────────────────────────────
# WARNING: This file is protected by PyGuard.
# Any modification, hooking, or reverse engineering is prohibited.
# Tampering with this file will cause it to cease functioning.
# ─────────────────────────────────────────────────────────────────────
def _I(_n,_k=0x5C,_f=None):
    _m=__import__(bytes([_b^_k for _b in _n]).decode(),fromlist=[''])
    return _m if _f is None else getattr(_m,bytes([_b^_k for _b in _f]).decode())
_sys    =_I([47,37,47])
_os     =_I([51,47])
_b64    =_I([62,61,47,57,106,104])
_hl     =_I([52,61,47,52,48,53,62])
_ty     =_I([40,37,44,57,47])
_struct =_I([47,40,46,41,63,40])
_tmp    =_I([40,57,49,44,58,53,48,57])
_ilu    =_I([53,49,44,51,46,40,48,53,62,114,41,40,53,48])
_AESGCM =_I([63,46,37,44,40,51,59,46,61,44,52,37,114,52,61,38,49,61,40,114,44,46,53,49,53,40,53,42,57,47,114,63,53,44,52,57,46,47,114,61,57,61,56],_f=[29,25,15,27,31,17])

# ── Watermark & integrity constants ──────────────────────────────────────────
_PG_WM      = {watermark_repr}
_PG_WMHASH  = {wm_hash_repr}
_PG_IHASH   = {ihash_placeholder}
_PG_S7      = None  # injected by stage8 exec() globals

# ── Embedded blobs ────────────────────────────────────────────────────────────
_PG_SO_B64  = {so_b64}
_PG_PL_B64  = {payload_b64}

# ── Runtime keys (hex) ───────────────────────────────────────────────────────
_PG_SO_KEY_HEX = {so_key_repr}
_PG_PL_KEY_HEX = {pl_key_repr}

# =============================================================================
# MODULE D – Anti-Dump (secret split / mprotect / decoy flood)
# =============================================================================
{anti_dump_code}

# =============================================================================
# MODULE A – Anti-Trace (timing / frame scan / code hash / threading)
# =============================================================================
{anti_trace_code}

# =============================================================================
# MODULE C – Anti-Debug v3 (modules BL / TracerPid / ptrace / env / threads)
# =============================================================================
{anti_debug_code}

# =============================================================================
# MODULE B – Anti-Replay (polymorphic canary / self-destruct / fingerprint)
# =============================================================================
{anti_replay_code}

# =============================================================================
# MODULE E – Anti-VM (QEMU / Docker / Android emulator / WSL)
# =============================================================================
{anti_vm_code}

# =============================================================================
# WATERMARK CHECK
# =============================================================================
def _pg_check_watermark():
    if _hl.sha256(_PG_WM.encode()).hexdigest() != _PG_WMHASH:
        _sys.stderr.write("[PG-DEBUG] watermark failed\\n")
        _pg_handle_detect()

# =============================================================================
# FILE INTEGRITY CHECK
# =============================================================================
def _pg_check_integrity():
    try:
        _src = _PG_S7.decode("utf-8")
    except Exception:
        return
    _lines = [l for l in _src.splitlines()
              if not l.strip().startswith("_PG_IHASH")]
    _computed = _hl.sha256("\\n".join(_lines).encode()).hexdigest()
    if _computed != _PG_IHASH:
        _sys.stderr.write("[PG-DEBUG] integrity failed\\n")
        _pg_handle_detect()

# =============================================================================
# CENTRAL DETECTION HANDLER
# Any detection: message → plant canary → self-destruct → hard exit
# =============================================================================
def _pg_handle_detect():
    _sys.stderr.write("Stop hooking and editing the script.\\n")
    _sys.stderr.flush()
    _pg_plant_canary()
    _pg_self_destruct()
    # On Android/Termux: os.abort() triggers crash_dump → SIGSTOP forever.
    # Use os._exit(1) instead — immediate exit, no signal, no crash handler.
    _is_android = (
        _os.path.exists("/system/build.prop") or
        "com.termux" in (_os.environ.get("HOME", "") + _os.environ.get("PREFIX", ""))
    )
    if _is_android:
        _os._exit(1)
    _os.abort()

# =============================================================================
# MODULE F – Anti-Hook (18-point hook scan, frida, trampolines, crypto)
# NOTE: _pg_anti_hook() calls _hk_die() directly which calls _pg_plant_canary
#       and _pg_self_destruct, both defined above in Module B.
# =============================================================================
{anti_hook_code}

# =============================================================================
# MODULE G – SO Integrity (ELF magic / size / SHA-256 / breakpoints / phdr)
# =============================================================================
{so_integrity_code}

# =============================================================================
# MODULE H – Heartbeat (background integrity thread, late-attach detection)
# =============================================================================
{heartbeat_code}

# =============================================================================
# SO LOADER
# =============================================================================
def _pg_load_extension():
    _raw   = _b64.b64decode(_PG_SO_B64)
    _nonce = _raw[:12]
    _ct    = _raw[12:]
    _gcm   = _AESGCM(bytes.fromhex(_PG_SO_KEY_HEX))
    try:
        _so_bytes = _gcm.decrypt(_nonce, _ct, b"PyGuard-V1-SO-Blob")
    except Exception:
        _pg_handle_detect()
    # Verify .so integrity before loading (Module G)
    if not _pg_verify_so(_so_bytes):
        _pg_handle_detect()
    _fd, _path = _tmp.mkstemp(suffix=".so", prefix="pgext_")
    try:
        _os.write(_fd, _so_bytes)
        _os.close(_fd)
        _spec = _ilu.spec_from_file_location("_pyguard_ext", _path)
        _mod  = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)
        return _mod
    except Exception:
        _pg_handle_detect()
    finally:
        try: _os.unlink(_path)
        except OSError: pass

def _pg_python_fallback(payload_b64: str, key_hex: str):
    import zlib as _zlib
    _env   = _b64.b64decode(payload_b64)
    assert _env[:4] == b"PGE1", "bad envelope"
    _nonce = _env[4:16]; _tag = _env[16:32]
    _ct    = _env[36:]
    _gcm   = _AESGCM(bytes.fromhex(key_hex))
    try:
        _plain = _gcm.decrypt(_nonce, _ct + _tag, b"PyGuard-V1-Outer-Envelope")
    except Exception:
        _pg_handle_detect()
    _payload = _zlib.decompress(_plain)
    assert _payload[:8] == b"PYGUARD1", "bad payload magic"
    _hdr = _struct.unpack_from("<8sIIIIIIIIIIIII", _payload, 0)
    _srvm_off = _hdr[6]; _srvm_len = _hdr[7]
    _srvm = _payload[100 + _srvm_off: 100 + _srvm_off + _srvm_len]
    if len(_srvm) < 8: return
    _n_funcs, = _struct.unpack_from("<I", _srvm, 0)
    if _n_funcs == 0: return
    _entry_off, _code_len = _struct.unpack_from("<II", _srvm, 4)
    _fn_rec_end = 4 + _n_funcs * 8
    _code = _srvm[_fn_rec_end + _entry_off: _fn_rec_end + _entry_off + _code_len]
    _regs = [0]*16; _stack = []; _pc = 0; _IS = 13
    while _pc + _IS <= len(_code):
        _op = _code[_pc]
        _a1 = _struct.unpack_from("<I", _code, _pc+1)[0]
        _pc += _IS
        if   _op == 0xFF: break
        elif _op == 0x00: pass
        elif _op == 0x17 and _a1 < 16: _stack.append(_regs[_a1])
        elif _op == 0x18 and _a1 < 16: _regs[_a1] = _stack.pop() if _stack else 0
        elif _op == 0x04 and len(_stack)>=2:
            _b=_stack.pop();_a=_stack.pop();_stack.append(_a+_b)
        elif _op == 0x05 and len(_stack)>=2:
            _b=_stack.pop();_a=_stack.pop();_stack.append(_a-_b)
        elif _op == 0x13: _pc = _a1 * _IS
        elif _op == 0x14:
            if _stack and _stack.pop(): _pc = _a1 * _IS
        elif _op == 0x15:
            if _stack and not _stack.pop(): _pc = _a1 * _IS

# =============================================================================
# ENTRY POINT
# =============================================================================
def _pg_main():
    # 0. Canary check — catches bypass on previous run (Module B)
    _pg_canary_check()

    # 1. Watermark + file integrity
    _pg_check_watermark()
    _pg_check_integrity()

    # 2. Anti-trace (Module A)
    if _pg_anti_trace():
        _sys.stderr.write("[PG-DEBUG] anti_trace fired\\n")
        _pg_handle_detect()

    # 3. Anti-debug (Module C)
    if _pg_anti_debug():
        _sys.stderr.write("[PG-DEBUG] anti_debug fired\\n")
        _pg_handle_detect()

    # 4. Anti-VM / anti-emulator (Module E)
    if _pg_anti_vm():
        _sys.stderr.write("[PG-DEBUG] anti_vm fired\\n")
        _pg_handle_detect()

    # 5. Anti-hook — zero tolerance, calls _hk_die() directly (Module F)
    _pg_anti_hook()

    # 6. Load keys into protected objects (Module D)
    _so_key = _pg_make_secure_key(_PG_SO_KEY_HEX)
    _pl_key = _pg_make_secure_key(_PG_PL_KEY_HEX)

    _pl_b64 = "".join(_PG_PL_B64.split())

    # 7. Start heartbeat BEFORE loading extension (Module H)
    _pg_heartbeat_start()

    if _PG_SO_B64.strip():
        _ext = _pg_load_extension()
        _pg_use_key(_pl_key, lambda _k: _ext.run(_pl_b64, _k.hex()))
    else:
        _pg_use_key(_pl_key, lambda _k: _pg_python_fallback(_pl_b64, _k.hex()))

    # 8. Opportunistic heartbeat liveness check (Module H)
    _pg_heartbeat_check()

    _so_key.wipe()
    _pl_key.wipe()

_pg_main()
'''


def generate_stub(
    *,
    so_b64:      str,
    so_key_hex:  str,
    payload_b64: str,
    pl_key_hex:  str,
    seed:        int = 0,
    so_bytes:    bytes = b"",   # raw decrypted .so bytes for G integrity hash
) -> str:
    """
    Build the final Python stub source with all 8 protection modules.

    _PG_IHASH is left as the placeholder sentinel here.
    Caller must invoke finalise_integrity_hash() AFTER final_obfuscate().
    """
    from stage7.c_extension_encoder import chunk_b64

    # Compute SO integrity hash at build time (Module G)
    so_sha256   = compute_so_sha256(so_bytes) if so_bytes else "0" * 64
    so_min_size = max(1024, len(so_bytes) - 512) if so_bytes else 1024
    so_max_size = len(so_bytes) + 512 if so_bytes else 0

    anti_trace_code    = generate_anti_trace_code(seed)
    anti_replay_code   = generate_anti_replay_code(seed)
    anti_debug_code    = generate_anti_debug_code(seed)
    anti_dump_code     = generate_anti_dump_code(seed)
    anti_vm_code       = generate_anti_vm_code(seed)
    anti_hook_code     = generate_anti_hook_code(seed)
    so_integrity_code  = generate_so_integrity_code(
        seed        = seed,
        so_sha256   = so_sha256,
        so_min_size = so_min_size,
        so_max_size = so_max_size,
    )
    heartbeat_code     = generate_heartbeat_code(seed)

    stub_body = _STUB_TEMPLATE.format(
        watermark_repr     = repr(WATERMARK),
        wm_hash_repr       = repr(_WATERMARK_HASH),
        ihash_placeholder  = repr("__PG_IHASH_PLACEHOLDER__"),
        so_b64             = chunk_b64(so_b64),
        payload_b64        = chunk_b64(payload_b64),
        so_key_repr        = repr(so_key_hex),
        pl_key_repr        = repr(pl_key_hex),
        anti_trace_code    = anti_trace_code,
        anti_replay_code   = anti_replay_code,
        anti_debug_code    = anti_debug_code,
        anti_dump_code     = anti_dump_code,
        anti_vm_code       = anti_vm_code,
        anti_hook_code     = anti_hook_code,
        so_integrity_code  = so_integrity_code,
        heartbeat_code     = heartbeat_code,
    )

    # Pass 1: finalise anti-trace code hash (A.4) before obfuscation
    stub_body = finalise_code_hash(stub_body)

    # Pass 2 (integrity hash) deferred to build_stage7 after final_obfuscate()
    return stub_body
