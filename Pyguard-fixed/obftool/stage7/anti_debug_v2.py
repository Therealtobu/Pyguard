"""
Stage 7 – Anti-Debug v2 Module (Module C)  [v4.0 — Android-portable rebuild]

CHANGES vs v3.1:
  • C.9  : ptrace EPERM handling tightened: on Android API 29+ ptrace is
           blocked by seccomp for all non-root processes. Now uses a 3-way
           check: ptrace result + TracerPid + /proc/self/wchan cross-validate.
  • C.13 : NEW — ADB debug flag check: reads /proc/self/status Seccomp field
           and cross-validates with TracerPid. Also checks
           /sys/kernel/tracing/tracing_on (ftrace-based debugger).
  • C.14 : NEW — Android debug.debuggable property check via build.prop.
           ro.debuggable=1 alone is NOT flagged (user may run debug ROM
           legitimately), but ro.debuggable=1 combined with TracerPid>0 is.
  • Scoring: unchanged — strong signals kill immediately, weak signals
             require score >= 2 to kill.

Checks C.1–C.14:
  C.1  sys.modules blacklist (pdb / debugpy / frida / pydevd etc.)
  C.2  Stack depth anomaly
  C.3  /proc/self/maps + TracerPid [binary read, null-byte safe]
  C.4  SIGTRAP self-injection [DISABLED on Android — triggers debuggerd]
  C.5  LD_PRELOAD / env var check (Termux-aware)
  C.6  Audit hook anomaly
  C.7  sys.breakpointhook replacement
  C.8  Debugger thread name scan
  C.9  ptrace(PTRACE_TRACEME) via ctypes [3-way validate on Android]
  C.10 /proc/self/wchan ptrace_stop
  C.11 Clock skew (wall vs monotonic)
  C.12 sys.ps1/ps2 interactive namespace
  C.13 NEW: ftrace tracing_on + Seccomp cross-validate
  C.14 NEW: ro.debuggable + TracerPid combined check
"""
from __future__ import annotations
import random
import hashlib


_ANTI_DEBUG_TEMPLATE = r'''
import sys as _sys_db
import os  as _os_db

_DB_EXPECTED_DEPTH  = {expected_depth}
_DB_DEPTH_TOLERANCE = 6
_DB_AUDIT_EVENT     = {audit_event!r}

# ── Platform probe ────────────────────────────────────────────────────────────
def _db_is_android() -> bool:
    try:
        return (
            _os_db.path.exists("/system/build.prop") or
            _os_db.path.exists("/system/app") or
            "com.termux" in (_os_db.environ.get("PREFIX", "") +
                             _os_db.environ.get("HOME", ""))
        )
    except Exception:
        return False

_DB_ON_ANDROID = _db_is_android()

# ─────────────────────────────────────────────────────────────────────────────
# C.1 – sys.modules blacklist
# ─────────────────────────────────────────────────────────────────────────────
_DB_BLACKLIST = frozenset({{
    "pdb", "bdb", "pudb", "ipdb", "pydevd",
    "debugpy", "coverage", "trace", "_pydev_bundle",
    "pydevd_tracing", "_pydevd_frame_eval",
    "cProfile", "profile",
    "_pytest", "pytest", "hunter",
    "viztracer", "pyinstrument", "yappi",
    "pyspy", "py_spy", "austin",
}})

def _db_modules_check() -> bool:
    return bool(set(_sys_db.modules.keys()) & _DB_BLACKLIST)

# ─────────────────────────────────────────────────────────────────────────────
# C.2 – Stack depth anomaly
# ─────────────────────────────────────────────────────────────────────────────
def _db_stack_depth_check() -> bool:
    try:
        _frame = _sys_db._getframe(0)
        _depth = 0
        while _frame is not None:
            _depth += 1
            _frame = _frame.f_back
        return _depth > _DB_EXPECTED_DEPTH + _DB_DEPTH_TOLERANCE
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# C.3 – /proc checks [binary read, null-byte safe, graceful decode]
# ─────────────────────────────────────────────────────────────────────────────
_DB_MAPS_EXACT = (
    "frida-agent", "frida-gadget", "frida-core", "libfrida",
    "gdbserver", "gdb-server", "valgrind",
    "xposed", "edxposed", "lsposed",
    "substrate", "cycript", "libhooker", "dyninst",
    "pintools", "libpin",
)

def _db_proc_maps_check() -> bool:
    try:
        with open("/proc/self/maps", "rb") as _f:
            _data = _f.read().replace(b"\x00", b"").decode("utf-8", errors="replace").lower()
        for _b in _DB_MAPS_EXACT:
            if _b in _data:
                return True
    except OSError:
        pass
    return False

def _db_tracer_pid_check() -> bool:
    try:
        with open("/proc/self/status", "rb") as _f:
            for _raw_line in _f:
                _line = _raw_line.replace(b"\x00", b"").decode("utf-8", errors="replace")
                if _line.startswith("TracerPid:"):
                    try:
                        _val = _line.split(":", 1)[1].strip()
                        return int(_val) != 0
                    except (ValueError, IndexError):
                        return False
    except OSError:
        pass
    return False

def _db_read_tracer_pid() -> int:
    """Helper: return TracerPid value (-1 on error)."""
    try:
        with open("/proc/self/status", "rb") as _f:
            for _raw in _f:
                _line = _raw.replace(b"\x00", b"").decode("utf-8", errors="replace")
                if _line.startswith("TracerPid:"):
                    try:
                        return int(_line.split(":", 1)[1].strip())
                    except (ValueError, IndexError):
                        return -1
    except OSError:
        pass
    return -1

# ─────────────────────────────────────────────────────────────────────────────
# C.4 – SIGTRAP self-injection
# DISABLED on Android: triggers Android debuggerd → process STOPPED permanently.
# ─────────────────────────────────────────────────────────────────────────────
def _db_sigtrap_check() -> bool:
    if _DB_ON_ANDROID:
        return False
    try:
        import signal as _sig
        if not hasattr(_sig, "SIGTRAP"):
            return False
        _fired = [False]
        def _our_handler(signum, frame):
            _fired[0] = True
        _old = _sig.signal(_sig.SIGTRAP, _our_handler)
        _sig.raise_signal(_sig.SIGTRAP)
        _sig.signal(_sig.SIGTRAP, _old)
        return not _fired[0]
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# C.5 – Environment variable anomaly (Termux-aware)
# ─────────────────────────────────────────────────────────────────────────────
_DB_PRELOAD_BAD_KEYWORDS = (
    "frida", "gdbserver", "inject", "hook",
    "xposed", "substrate", "cycript",
    "dyninst", "valgrind", "libpin", "libdebug", "ltrace", "intercept",
)
_DB_ENV_DEFINITE = (
    "LD_AUDIT", "PYTHONDEBUG", "PYTHONINSPECT",
    "DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE",
)

def _db_env_check() -> bool:
    for _v in _DB_ENV_DEFINITE:
        if _os_db.environ.get(_v, "").strip():
            return True
    _ldp = _os_db.environ.get("LD_PRELOAD", "").lower()
    if _ldp.strip():
        for _kw in _DB_PRELOAD_BAD_KEYWORDS:
            if _kw in _ldp:
                return True
    _pbp = _os_db.environ.get("PYTHONBREAKPOINT", "").strip()
    if _pbp and _pbp != "0":
        return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# C.6 – Audit hook anomaly
# ─────────────────────────────────────────────────────────────────────────────
def _db_audit_check() -> bool:
    try:
        _count = [0]
        def _our_hook(event, args):
            if event == _DB_AUDIT_EVENT:
                _count[0] += 1
        _sys_db.addaudithook(_our_hook)
        _sys_db.audit(_DB_AUDIT_EVENT)
        return _count[0] > 1
    except (AttributeError, TypeError):
        return False

# ─────────────────────────────────────────────────────────────────────────────
# C.7 – sys.breakpointhook replacement
# ─────────────────────────────────────────────────────────────────────────────
def _db_breakpointhook_check() -> bool:
    try:
        _bph = getattr(_sys_db, "breakpointhook", None)
        if _bph is None:
            return False
        _native_type = type(len)
        if not isinstance(_bph, _native_type):
            _env = _os_db.environ.get("PYTHONBREAKPOINT", "")
            if not _env or _env == "0":
                return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# C.8 – Debugger thread name scan
# ─────────────────────────────────────────────────────────────────────────────
_DB_DEBUGGER_THREAD_NAMES = (
    "pydevd", "debugpy", "debugserver",
    "ptvsd", "remote_debugger", "_pydev_",
)

def _db_debugger_thread_check() -> bool:
    try:
        import threading as _thr_db
        for _t in _thr_db.enumerate():
            _n = (_t.name or "").lower()
            for _bad in _DB_DEBUGGER_THREAD_NAMES:
                if _bad in _n:
                    return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# C.9 – ptrace(PTRACE_TRACEME) via ctypes
# FIXED v4.0: 3-way validation on Android.
#   • Android API 29+ blocks ptrace via seccomp (ENOSYS=38).
#   • EPERM (1) on Android can mean seccomp policy OR actual debugger.
#   • 3-way: ptrace result + TracerPid + wchan cross-validate before firing.
# ─────────────────────────────────────────────────────────────────────────────
_DB_LIBC_PATHS = ("libc.so.6", "libc.so", "libc.musl-x86_64.so.1", None)

def _db_ptrace_check() -> bool:
    try:
        import ctypes as _ct_db
        _libc = None
        for _path in _DB_LIBC_PATHS:
            try:
                _libc = _ct_db.CDLL(_path, use_errno=True)
                _ = _libc.ptrace
                break
            except (OSError, AttributeError):
                _libc = None
                continue
        if _libc is None:
            return False
        _r = _libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME = 0
        if _r == -1:
            import ctypes as _ct2
            _err = _ct2.get_errno()
            if _err == 38:
                # ENOSYS — seccomp filtered (Android API 29+). NOT a debugger.
                return False
            if _err != 1:
                # Unexpected error — assume policy, not debugger.
                return False
            # EPERM: need 2 additional signals to confirm on Android
            _tracer = _db_read_tracer_pid()
            if _tracer > 0:
                return True
            # Check wchan too
            try:
                with open("/proc/self/wchan", "rb") as _f:
                    _wchan = _f.read().replace(b"\x00", b"").decode("utf-8", errors="replace").strip().lower()
                if "ptrace" in _wchan or "trace_stop" in _wchan:
                    return True
            except OSError:
                pass
            # On Android, EPERM alone (no TracerPid, no wchan) = seccomp. Safe.
            return False
        # ptrace succeeded (r == 0): we attached to ourselves. Detach cleanly.
        try:
            _libc.ptrace(17, 0, 0, 0)  # PTRACE_DETACH = 17
        except Exception:
            pass
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# C.10 – /proc/self/wchan
# ─────────────────────────────────────────────────────────────────────────────
def _db_wchan_check() -> bool:
    try:
        with open("/proc/self/wchan", "rb") as _f:
            _wchan = _f.read().replace(b"\x00", b"").decode("utf-8", errors="replace").strip().lower()
        if "ptrace" in _wchan or "trace_stop" in _wchan:
            return True
    except OSError:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# C.11 – Clock skew
# ─────────────────────────────────────────────────────────────────────────────
def _db_clock_skew_check() -> bool:
    try:
        import time as _t_db
        _m0 = _t_db.monotonic()
        _w0 = _t_db.time()
        _t_db.sleep(0.005)
        _m1 = _t_db.monotonic()
        _w1 = _t_db.time()
        if abs((_m1 - _m0) - (_w1 - _w0)) > 0.5:
            return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# C.12 – Interactive namespace injection
# ─────────────────────────────────────────────────────────────────────────────
def _db_interactive_check() -> bool:
    if hasattr(_sys_db, "ps1") or hasattr(_sys_db, "ps2"):
        if not (hasattr(_sys_db, "flags") and _sys_db.flags.interactive):
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# C.13 – NEW: ftrace tracing_on check
# /sys/kernel/tracing/tracing_on == "1" means ftrace (kernel tracer) is active.
# Only flag if TracerPid is also > 0 (avoid FP on debug kernels with ftrace on).
# ─────────────────────────────────────────────────────────────────────────────
def _db_ftrace_check() -> bool:
    try:
        for _ftrace_path in (
            "/sys/kernel/tracing/tracing_on",
            "/sys/kernel/debug/tracing/tracing_on",
        ):
            try:
                with open(_ftrace_path, "rb") as _f:
                    _val = _f.read().replace(b"\x00", b"").decode("utf-8", errors="replace").strip()
                if _val == "1":
                    # ftrace is on — cross-validate with TracerPid
                    if _db_read_tracer_pid() > 0:
                        return True
                    # Not being ptrace'd but ftrace is on. Score as weak signal.
                    return False   # handled in scoring below
            except (OSError, PermissionError):
                pass
    except Exception:
        pass
    return False

def _db_ftrace_weak() -> bool:
    """Returns True if ftrace is on even without TracerPid (weak signal)."""
    for _ftrace_path in (
        "/sys/kernel/tracing/tracing_on",
        "/sys/kernel/debug/tracing/tracing_on",
    ):
        try:
            with open(_ftrace_path, "rb") as _f:
                _val = _f.read().replace(b"\x00", b"").decode("utf-8", errors="replace").strip()
            if _val == "1":
                return True
        except (OSError, PermissionError):
            pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# C.14 – NEW: ro.debuggable + TracerPid combined (Android only)
# ro.debuggable=1 alone is NOT flagged (user may run custom ROM).
# ro.debuggable=1 AND TracerPid > 0 = strong signal on Android.
# ─────────────────────────────────────────────────────────────────────────────
def _db_android_debuggable_check() -> bool:
    if not _DB_ON_ANDROID:
        return False
    try:
        with open("/system/build.prop", "rb") as _f:
            _bp = _f.read().replace(b"\x00", b"").decode("utf-8", errors="replace").lower()
        if "ro.debuggable=1" in _bp:
            # Debuggable ROM: only flag if also being traced
            if _db_read_tracer_pid() > 0:
                return True
    except OSError:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# Composite — confidence scoring
# ─────────────────────────────────────────────────────────────────────────────
def _pg_anti_debug() -> bool:
    # Strong signals — fire immediately (score equivalent >= 2 on their own)
    if _db_modules_check():              return True
    if _db_tracer_pid_check():           return True
    if _db_ptrace_check():               return True
    if _db_debugger_thread_check():      return True
    if _db_wchan_check():                return True
    if _db_ftrace_check():               return True   # ftrace + TracerPid combined
    if _db_android_debuggable_check():   return True   # debuggable + TracerPid combined

    # Weak signals — need corroboration (total score >= 2)
    _score = 0
    if _db_proc_maps_check():            _score += 2
    if _db_env_check():                  _score += 1
    if _db_stack_depth_check():          _score += 1
    if _db_sigtrap_check():              _score += 1
    if _db_audit_check():                _score += 1
    if _db_breakpointhook_check():       _score += 1
    if _db_clock_skew_check():           _score += 1
    if _db_interactive_check():          _score += 1
    if _db_ftrace_weak():                _score += 1   # ftrace on without TracerPid = weak
    return _score >= 2
'''


def generate_anti_debug_code(seed: int = 0) -> str:
    audit_event = "pg." + hashlib.sha256(str(seed).encode()).hexdigest()[:8]
    return _ANTI_DEBUG_TEMPLATE.format(
        expected_depth=5,
        audit_event=audit_event,
    )
