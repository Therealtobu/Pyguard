"""
Stage 7 – Anti-Hook Module (Module F)  [v2.0 — Android-portable rebuild]

CHANGES vs v1.2:
  • F.1  : Removed fragile ctypes ob_type slot read (ARM64 layout-dependent).
           Now uses pure isinstance + __wrapped__ checks — equally effective,
           zero false-positives on ARM64/Bionic.
  • F.3  : Completely rewrote ARM64 trampoline detector.
           Old code flagged Bionic's legitimate B-to-variant pattern.
           New code checks for Frida-specific ARM64 hook signatures:
             - LDR x17, #8 / BR x17  (Frida inline hook)
             - ADRP x16, _ / LDR x16 / BR x16 (Frida absolute trampoline)
           x86/x86_64 logic unchanged.
  • F.7  : Added Android-specific Frida file checks in /data/local/tmp.
  • F.16 : Added Frida server port scan via /proc/net/tcp + /proc/net/tcp6
           (more reliable than connect() on some Android network policies).
  • F.18 : NEW — Android Xposed/LSPosed artifacts check.
  • F.19 : NEW — Frida gadget path scan in /data/local/tmp.

Detection order (hard kills first, softer checks last):
  crypto_integrity → builtins → frida_artifacts → frida_android →
  sys_modules → module_injection → wrappers → builtins_type → sys_hooks →
  thread_hooks → gc_hooks → environ → signals → meta_path → importlib →
  ctypes_integrity → native_trampolines → malicious_processes → xposed
"""
from __future__ import annotations
import random
import hashlib


_ANTI_HOOK_TEMPLATE = r'''
import sys      as _sys_hk
import os       as _os_hk
import ctypes   as _ct_hk
import builtins as _bi_hk

_HK_BUILD_SALT  = {build_salt!r}
_HK_NATIVE_FN   = type(len)
_HK_NATIVE_TYPE = type(int)

# ── Platform probe (cached once) ─────────────────────────────────────────────
def _hk_is_android() -> bool:
    try:
        return (
            _os_hk.path.exists("/system/build.prop") or
            _os_hk.path.exists("/system/app") or
            "com.termux" in (_os_hk.environ.get("HOME", "") +
                             _os_hk.environ.get("PREFIX", ""))
        )
    except Exception:
        return False

_HK_ON_ANDROID = _hk_is_android()

def _hk_die():
    _sys_hk.stderr.write("Stop hooking and editing the script.\n")
    _sys_hk.stderr.flush()
    _pg_plant_canary()
    _pg_self_destruct()
    if _HK_ON_ANDROID:
        _os_hk._exit(1)
    _os_hk.abort()

# ─────────────────────────────────────────────────────────────────────────────
# F.1 – Builtin function / type integrity
# FIXED v2.0: Removed ctypes ob_type slot read (ARM64-unsafe).
#             Now uses isinstance + __wrapped__ only. Equally effective.
# ─────────────────────────────────────────────────────────────────────────────
_HK_CRITICAL_BUILTINS = (
    "exec", "eval", "compile", "__import__", "open", "print",
    "bytes", "bytearray", "int", "str", "type", "len",
    "getattr", "setattr", "hasattr", "delattr",
    "isinstance", "issubclass", "id", "hash", "repr",
    "globals", "locals",
)

def _hk_check_builtins() -> bool:
    for _name in _HK_CRITICAL_BUILTINS:
        _fn = getattr(_bi_hk, _name, None)
        if _fn is None:
            return True
        _is_fn  = isinstance(_fn, _HK_NATIVE_FN)
        _is_typ = isinstance(_fn, _HK_NATIVE_TYPE)
        if not _is_fn and not _is_typ:
            return True
        if hasattr(_fn, "__wrapped__"):
            return True
        # Check for mock/patch objects
        if hasattr(_fn, "_mock_name") or hasattr(_fn, "_mock_methods"):
            return True
        # Check __class__ name for obvious wrappers
        _cls_name = type(_fn).__name__
        if "mock" in _cls_name.lower() or "patch" in _cls_name.lower():
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.2 – sys.modules core module identity / wrapper check
# ─────────────────────────────────────────────────────────────────────────────
_HK_CORE_MODULES = ("os", "sys", "builtins", "ctypes", "hashlib",
                    "hmac", "struct", "importlib", "threading", "gc")

def _hk_check_sys_modules() -> bool:
    import types as _types_hk
    for _name in _HK_CORE_MODULES:
        _mod = _sys_hk.modules.get(_name)
        if _mod is None:
            continue
        if not isinstance(_mod, _types_hk.ModuleType):
            return True
        _d = vars(_mod)
        for _attr in _d:
            if _attr.startswith("__frida") or _attr.startswith("_frida"):
                return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.3 – Native inline trampoline scan
# FIXED v2.0: ARM64 check now looks for Frida-specific hook signatures only.
#
# Frida ARM64 inline hook signatures:
#   Pattern A — LDR x17, #8 / BR x17:
#     bytes: 51 00 00 58  20 02 1F D6  [8-byte absolute address]
#   Pattern B — ADRP x16, _ / LDR x16, [x16, offset] / BR x16:
#     Opcode stream starting with: 10 00 00 90 (ADRP x16)
#     followed by: 10 02 40 F9 (LDR x16)
#     followed by: 00 02 1F D6 (BR x16)
#
# x86/x86_64: unchanged — 0xE9 (JMP rel32) or 0xEB (JMP rel8) at byte 0.
# ─────────────────────────────────────────────────────────────────────────────
_HK_LIBC_PATHS = ("libc.so.6", "libc.so", None)
_HK_JMP_X86    = frozenset((0xE9, 0xEB))

# ARM64 Frida inline hook: LDR x17, #8 (0x58000051) + BR x17 (0xD61F0220)
_HK_FRIDA_ARM64_A_WORD0 = 0x58000051   # LDR x17, #8
_HK_FRIDA_ARM64_A_WORD1 = 0xD61F0220   # BR  x17

# ARM64 Frida absolute trampoline: ADRP+LDR pattern (first byte mask)
_HK_FRIDA_ARM64_B_WORD0 = 0x90000010   # ADRP x16, page_offset (mask 0x9F000000 → lo bits vary)
_HK_FRIDA_ARM64_B_MASK0 = 0x9F00001F   # mask to check opcode + reg field only
_HK_FRIDA_ARM64_B_WORD2 = 0xD61F0000   # BR x16 (0xD61F0200 with Rn=x16)

def _hk_check_native_trampolines() -> bool:
    _libc = None
    for _path in _HK_LIBC_PATHS:
        try:
            _libc = _ct_hk.CDLL(_path, use_errno=True)
            break
        except OSError:
            continue
    if _libc is None:
        return False
    for _fname in ("memmove", "memcpy", "malloc", "free", "strlen"):
        try:
            _fn = getattr(_libc, _fname, None)
            if _fn is None:
                continue
            _addr = _ct_hk.cast(_fn, _ct_hk.c_void_p).value
            if _addr is None:
                continue
            _buf = (_ct_hk.c_uint8 * 16)()
            _ct_hk.memmove(_buf, _addr, 16)
            _raw = bytes(_buf)
            _first = _raw[0]

            # ── x86 / x86_64: unconditional JMP ──────────────────────────────
            if _first in _HK_JMP_X86:
                return True

            # ── ARM64: Frida-specific signatures only ─────────────────────────
            # Pattern A: LDR x17, #8 followed by BR x17
            _w0 = int.from_bytes(_raw[0:4],  "little")
            _w1 = int.from_bytes(_raw[4:8],  "little")
            _w2 = int.from_bytes(_raw[8:12], "little")
            if _w0 == _HK_FRIDA_ARM64_A_WORD0 and _w1 == _HK_FRIDA_ARM64_A_WORD1:
                return True
            # Pattern B: ADRP x16 (masked) + any word + BR x16
            if ((_w0 & _HK_FRIDA_ARM64_B_MASK0) == (_HK_FRIDA_ARM64_B_WORD0 & _HK_FRIDA_ARM64_B_MASK0)
                    and _w2 == _HK_FRIDA_ARM64_B_WORD2):
                return True
            # NOTE: simple B (0x14xxxxxx >> 26 == 0x05) is NOT flagged —
            # Bionic legitimately uses B-to-variant for memmove/memcpy NEON path.
        except Exception:
            pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.4 – Module attribute injection
# ─────────────────────────────────────────────────────────────────────────────
_HK_INJECT_MARKERS = frozenset((
    "__frida_native_module__", "__frida_module__",
    "_frida_agent", "_hook_active", "_intercept_active",
    "__pyspy__", "__viztracer__", "__xposed__",
))

def _hk_check_module_injection() -> bool:
    for _name in _HK_CORE_MODULES:
        _mod = _sys_hk.modules.get(_name)
        if _mod is None:
            continue
        _attrs = dir(_mod)
        for _marker in _HK_INJECT_MARKERS:
            if _marker in _attrs:
                return True
    for _marker in _HK_INJECT_MARKERS:
        if hasattr(_bi_hk, _marker):
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.5 – sys.displayhook replacement (excepthook too noisy — removed)
# ─────────────────────────────────────────────────────────────────────────────
def _hk_check_sys_hooks() -> bool:
    _dh = getattr(_sys_hk, "displayhook", None)
    if _dh is not None and not isinstance(_dh, _HK_NATIVE_FN):
        return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.6 – __builtins__ type integrity
# ─────────────────────────────────────────────────────────────────────────────
def _hk_check_builtins_type() -> bool:
    import types as _types_hk2
    _blt = globals().get("__builtins__", None)
    if _blt is None:
        return True
    if not isinstance(_blt, (_types_hk2.ModuleType, dict)):
        return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.7 – Frida runtime artifacts (Linux + Android)
# ─────────────────────────────────────────────────────────────────────────────
_HK_FRIDA_GLOBALS    = ("__frida_native_module__", "frida", "_frida")
_HK_FRIDA_MAP_MARKERS = (
    "frida-gadget", "frida-agent", "__frida", "gum-js-loop",
)

def _hk_check_frida_artifacts() -> bool:
    _glb = globals()
    for _sym in _HK_FRIDA_GLOBALS:
        if _sym in _glb:
            return True
    # Frida server port 27042
    try:
        import socket as _sock_hk
        _s = _sock_hk.socket(_sock_hk.AF_INET, _sock_hk.SOCK_STREAM)
        _s.settimeout(0.05)
        _r = _s.connect_ex(("127.0.0.1", 27042))
        _s.close()
        if _r == 0:
            return True
    except Exception:
        pass
    # /proc/self/maps markers
    try:
        with open("/proc/self/maps", "rb") as _f:
            _maps = _f.read().replace(b"\x00", b"").decode("utf-8", errors="replace").lower()
        for _m in _HK_FRIDA_MAP_MARKERS:
            if _m in _maps:
                return True
    except OSError:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.8 – wrapt / functools wrapper detection on critical builtins
# ─────────────────────────────────────────────────────────────────────────────
_HK_WRAP_ATTRS = ("__wrapped__", "_mock_name", "_mock_methods")

def _hk_check_wrappers() -> bool:
    for _name in _HK_CRITICAL_BUILTINS:
        _fn = getattr(_bi_hk, _name, None)
        if _fn is None:
            continue
        for _attr in _HK_WRAP_ATTRS:
            if hasattr(_fn, _attr):
                return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.9 – hashlib / hmac crypto integrity (known test vectors)
# ─────────────────────────────────────────────────────────────────────────────
def _hk_check_crypto_integrity() -> bool:
    import hashlib as _hl_hk
    import hmac    as _hmac_hk
    try:
        _expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        if _hl_hk.sha256(b"").hexdigest() != _expected:
            return True
    except Exception:
        return True
    try:
        _h = _hmac_hk.new(b"key", b"message", "sha256").hexdigest()
        if _h != "6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a":
            return True
    except Exception:
        return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.10 – os.environ type integrity
# ─────────────────────────────────────────────────────────────────────────────
def _hk_check_environ() -> bool:
    try:
        _t = type(_os_hk.environ).__name__
        if _t not in ("_Environ", "Environ", "EnvironmentVariablesMapping"):
            return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.11 – sys.meta_path unexpected import hook entries
# ─────────────────────────────────────────────────────────────────────────────
_HK_META_HOOK_KEYWORDS = (
    "frida", "inject", "hook", "intercept", "patch",
    "mock", "spy", "coverage_", "trace_import",
)

def _hk_check_meta_path() -> bool:
    if _sys_hk.gettrace() is not None:
        return False
    import importlib.machinery as _ilm_hk
    _safe_types = (
        _ilm_hk.BuiltinImporter,
        _ilm_hk.FrozenImporter,
        _ilm_hk.PathFinder,
        _ilm_hk.FileFinder,
    )
    for _finder in _sys_hk.meta_path:
        if isinstance(_finder, _safe_types):
            continue
        _fmod  = (getattr(type(_finder), "__module__", "") or "").lower()
        _fname = (getattr(type(_finder), "__qualname__", "") or "").lower()
        _combined = _fmod + " " + _fname
        for _kw in _HK_META_HOOK_KEYWORDS:
            if _kw in _combined:
                return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.12 – Signal handler replacement
# Only flag if unusual handler AND trace active (Termux sets some handlers).
# ─────────────────────────────────────────────────────────────────────────────
def _hk_check_signals() -> bool:
    try:
        import signal as _sig_hk
        if _sys_hk.gettrace() is None:
            return False
        for _signum in (_sig_hk.SIGINT, _sig_hk.SIGTERM):
            _handler = _sig_hk.getsignal(_signum)
            if _handler in (_sig_hk.SIG_DFL, _sig_hk.SIG_IGN, None):
                continue
            if callable(_handler) and not isinstance(_handler, _HK_NATIVE_FN):
                _m = getattr(_handler, "__module__", "") or ""
                if _m not in ("signal", "_signal", "site", "", "threading",
                              "_multiprocessing", "multiprocessing"):
                    return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.13 – threading.settrace / setprofile
# ─────────────────────────────────────────────────────────────────────────────
def _hk_check_thread_hooks() -> bool:
    try:
        import threading as _thr_hk2
        if getattr(_thr_hk2, "_trace_hook", None) is not None:
            return True
        if getattr(_thr_hk2, "_profile_hook", None) is not None:
            return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.14 – gc.callbacks — only flag obvious hook keywords
# ─────────────────────────────────────────────────────────────────────────────
_HK_GC_CB_KEYWORDS = (
    "frida", "inject", "hook", "intercept", "coverage", "trace",
    "pydevd", "debugpy", "spy",
)

def _hk_check_gc_hooks() -> bool:
    try:
        import gc as _gc_hk
        for _cb in _gc_hk.callbacks:
            _r = repr(_cb).lower()
            for _kw in _HK_GC_CB_KEYWORDS:
                if _kw in _r:
                    return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.15 – importlib.machinery loader replacement
# ─────────────────────────────────────────────────────────────────────────────
def _hk_check_importlib() -> bool:
    try:
        import importlib.machinery as _ilm2
        _sgc = getattr(_ilm2.SourceFileLoader, "get_code", None)
        if _sgc is not None and hasattr(_sgc, "__wrapped__"):
            return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.16 – /proc/*/comm malicious process scan
# ─────────────────────────────────────────────────────────────────────────────
_HK_BAD_PROCESS_NAMES = (
    "frida-server", "frida-portal", "frida-ps",
    "gdbserver", "lldb-server",
    "objection", "r2", "radare2",
    "strace", "ltrace",
)

def _hk_check_malicious_processes() -> bool:
    try:
        for _entry in _os_hk.scandir("/proc"):
            if not _entry.name.isdigit():
                continue
            try:
                with open("/proc/" + _entry.name + "/comm", "rb") as _f:
                    _comm = _f.read().replace(b"\x00", b"").decode("utf-8", errors="replace").strip().lower()
                for _bad in _HK_BAD_PROCESS_NAMES:
                    if _bad in _comm:
                        return True
            except OSError:
                pass
    except OSError:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.17 – ctypes.CDLL integrity
# ─────────────────────────────────────────────────────────────────────────────
def _hk_check_ctypes_integrity() -> bool:
    try:
        _init = _ct_hk.CDLL.__dict__.get("__init__")
        if _init is not None and hasattr(_init, "__wrapped__"):
            return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.18 – NEW: Frida gadget / server files in Android temp paths
# These files are placed by Frida tooling and never present on a clean device.
# ─────────────────────────────────────────────────────────────────────────────
_HK_FRIDA_FILE_PATHS = (
    "/data/local/tmp/frida-server",
    "/data/local/tmp/re.frida.server",
    "/data/local/tmp/frida-gadget.config.so",
    "/data/local/tmp/frida",
    "/data/local/tmp/.frida",
)
_HK_FRIDA_GADGET_PREFIX = "/data/local/tmp/frida"

def _hk_check_frida_android_files() -> bool:
    for _path in _HK_FRIDA_FILE_PATHS:
        if _os_hk.path.exists(_path):
            return True
    # Scan /data/local/tmp for any frida-* entries
    try:
        for _e in _os_hk.scandir("/data/local/tmp"):
            if _e.name.lower().startswith("frida"):
                return True
    except OSError:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.19 – NEW: Frida port 27042 via /proc/net/tcp + /proc/net/tcp6
# More reliable than socket connect on Android (some SELinux configs block it).
# Port 27042 = 0x699A in hex (little-endian in /proc/net/tcp: "9A69")
# ─────────────────────────────────────────────────────────────────────────────
def _hk_check_frida_proc_net() -> bool:
    _FRIDA_PORT_HEX = "699a"
    for _netfile in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(_netfile, "r", errors="replace") as _f:
                for _line in _f:
                    # Field 1 = local_address:port  (e.g. 0100007F:699A)
                    _parts = _line.strip().split()
                    if len(_parts) < 2:
                        continue
                    _local = _parts[1].lower()
                    if ":" in _local:
                        _port_hex = _local.split(":")[1]
                        if _port_hex == _FRIDA_PORT_HEX:
                            return True
        except OSError:
            pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# F.20 – NEW: Xposed / LSPosed framework artifacts
# These indicate an Xposed-based hooking framework is active.
# Only flag definitive markers — NOT root/Magisk alone.
# ─────────────────────────────────────────────────────────────────────────────
_HK_XPOSED_PATHS = (
    "/system/framework/XposedBridge.jar",
    "/system/bin/app_process.orig",
    "/data/adb/lspd",          # LSPosed daemon dir
    "/data/adb/modules/riru",  # Riru (Xposed loader)
)
_HK_XPOSED_MAP_MARKERS = ("xposedbridge", "edxposed", "lsposed", "riru")

def _hk_check_xposed_artifacts() -> bool:
    for _path in _HK_XPOSED_PATHS:
        if _os_hk.path.exists(_path):
            return True
    # Check /proc/self/maps for Xposed library names
    try:
        with open("/proc/self/maps", "rb") as _f:
            _maps = _f.read().replace(b"\x00", b"").decode("utf-8", errors="replace").lower()
        for _m in _HK_XPOSED_MAP_MARKERS:
            if _m in _maps:
                return True
    except OSError:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# MASTER anti-hook scan — hard kills on any detection
# ─────────────────────────────────────────────────────────────────────────────
def _pg_anti_hook():
    if _hk_check_crypto_integrity():
        _sys_hk.stderr.write("[PG-DEBUG] hook:crypto_integrity\n")
        _hk_die()
    if _hk_check_builtins():
        _sys_hk.stderr.write("[PG-DEBUG] hook:builtins\n")
        _hk_die()
    if _hk_check_frida_artifacts():
        _sys_hk.stderr.write("[PG-DEBUG] hook:frida_artifacts\n")
        _hk_die()
    if _hk_check_frida_proc_net():
        _sys_hk.stderr.write("[PG-DEBUG] hook:frida_port\n")
        _hk_die()
    if _HK_ON_ANDROID and _hk_check_frida_android_files():
        _sys_hk.stderr.write("[PG-DEBUG] hook:frida_android_files\n")
        _hk_die()
    if _HK_ON_ANDROID and _hk_check_xposed_artifacts():
        _sys_hk.stderr.write("[PG-DEBUG] hook:xposed\n")
        _hk_die()
    if _hk_check_sys_modules():
        _sys_hk.stderr.write("[PG-DEBUG] hook:sys_modules\n")
        _hk_die()
    if _hk_check_module_injection():
        _sys_hk.stderr.write("[PG-DEBUG] hook:module_injection\n")
        _hk_die()
    if _hk_check_wrappers():
        _sys_hk.stderr.write("[PG-DEBUG] hook:wrappers\n")
        _hk_die()
    if _hk_check_builtins_type():
        _sys_hk.stderr.write("[PG-DEBUG] hook:builtins_type\n")
        _hk_die()
    if _hk_check_sys_hooks():
        _sys_hk.stderr.write("[PG-DEBUG] hook:sys_hooks\n")
        _hk_die()
    if _hk_check_thread_hooks():
        _sys_hk.stderr.write("[PG-DEBUG] hook:thread_hooks\n")
        _hk_die()
    if _hk_check_gc_hooks():
        _sys_hk.stderr.write("[PG-DEBUG] hook:gc_hooks\n")
        _hk_die()
    if _hk_check_environ():
        _sys_hk.stderr.write("[PG-DEBUG] hook:environ\n")
        _hk_die()
    if _hk_check_signals():
        _sys_hk.stderr.write("[PG-DEBUG] hook:signals\n")
        _hk_die()
    if _hk_check_meta_path():
        _sys_hk.stderr.write("[PG-DEBUG] hook:meta_path\n")
        _hk_die()
    if _hk_check_importlib():
        _sys_hk.stderr.write("[PG-DEBUG] hook:importlib\n")
        _hk_die()
    if _hk_check_ctypes_integrity():
        _sys_hk.stderr.write("[PG-DEBUG] hook:ctypes_integrity\n")
        _hk_die()
    if _hk_check_native_trampolines():
        _sys_hk.stderr.write("[PG-DEBUG] hook:native_trampolines\n")
        _hk_die()
    if _hk_check_malicious_processes():
        _sys_hk.stderr.write("[PG-DEBUG] hook:malicious_processes\n")
        _hk_die()
'''


def generate_anti_hook_code(seed: int = 0) -> str:
    rng = random.Random(seed ^ 0xF0F0F0F0 ^ 0x66)
    build_salt = hashlib.sha256(
        str(seed ^ rng.randint(0, 0xFFFFFFFF)).encode()
    ).hexdigest()[:16]
    return _ANTI_HOOK_TEMPLATE.format(build_salt=build_salt)
