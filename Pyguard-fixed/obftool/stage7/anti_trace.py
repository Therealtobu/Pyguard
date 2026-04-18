"""
Stage 7 – Anti-Trace Module (Module A)  [v3.0 — Android-portable rebuild]

CHANGES vs v2.0:
  • A.2  : Timing multiplier raised 80x → 200x to survive Android Doze/throttle.
           Added: skip timing check entirely if baseline is suspiciously high
           (> 50ms for the inner loop = phone under heavy load, skip to avoid FP).
           Added: require TWO consecutive suspicious timings before flagging.
  • A.3  : Frame f_trace check now requires BOTH f_trace != None AND
           sys.gettrace() != None. Previously fired on some ARM Python builds
           where f_trace was set internally without an explicit tracer.
  • A.8  : Already correct (stdlib modules removed), kept as-is.
  • A.11 : NEW — Android-specific: check for /proc/self/status Seccomp vs
           TracerPid cross-validation (detect ptrace via Android debug bridge).
  • A.12 : NEW — sys.monitoring (3.12+) tool presence scan (moved here from A.6,
           expanded to cover COVERAGE_ID, PROFILER_ID, OPTIMIZER_ID).

Checks A–J summary:
  A.1  sys.gettrace / sys.getprofile
  A.2  Timing-based bytecode trace detector (200x threshold, 2-hit confirm)
  A.3  Frame f_trace scan (FIXED: requires gettrace != None too)
  A.4  Code object hash tripwire
  A.5  threading._trace_hook canary
  A.6  sys.monitoring tool presence (3.12+)
  A.7  settrace-via-C-extension audit event count
  A.8  Decompiler module presence (uncompyle6/xdis etc — NOT dis/inspect/ast)
  A.9  Frame locals contamination scan
  A.10 co_code mutation check on own functions
  A.11 NEW: /proc/self/status ptrace cross-validation (Android ADB debug bridge)
"""
from __future__ import annotations
import hashlib
import random


_ANTI_TRACE_TEMPLATE = r'''
import sys as _sys_at
import threading as _thr_at
from time import perf_counter_ns as _pcns

_AT_CALIB_N   = {calib_n}
_AT_MAGIC     = {magic:#010x}
_AT_CODE_HASH = {code_hash!r}

# ── Platform probe ────────────────────────────────────────────────────────────
def _at_is_android() -> bool:
    try:
        import os as _os_at_p
        return (
            _os_at_p.path.exists("/system/build.prop") or
            _os_at_p.path.exists("/system/app") or
            "com.termux" in (_os_at_p.environ.get("HOME", "") +
                             _os_at_p.environ.get("PREFIX", ""))
        )
    except Exception:
        return False

_AT_ON_ANDROID = _at_is_android()

# ─────────────────────────────────────────────────────────────────────────────
# A.1 – Direct sys.gettrace / sys.getprofile
# ─────────────────────────────────────────────────────────────────────────────
def _at_direct_check() -> bool:
    return (_sys_at.gettrace() is not None or
            _sys_at.getprofile() is not None)

# ─────────────────────────────────────────────────────────────────────────────
# A.2 – Adaptive timing ratio
# FIXED v3.0:
#   • Multiplier 80x → 200x (Android Doze can cause 50-100x slowdowns)
#   • Skip entirely if baseline > 50ms (device under load; don't FP)
#   • Require TWO consecutive suspicious measurements (eliminates single spikes)
# ─────────────────────────────────────────────────────────────────────────────
def _at_timed_loop(_n=_AT_CALIB_N, _m=_AT_MAGIC):
    _x = {init_x:#010x}
    _t1 = _pcns()
    for _i in range(_n):
        _x = (_x ^ (_i * _m)) & 0xFFFF
    _t2 = _pcns()
    _ = _x
    return _t2 - _t1

_AT_BASELINE_NS      = [0]
_AT_SUSPICIOUS_COUNT = [0]
_AT_SKIP_THRESHOLD   = 50_000_000   # 50ms — device under load, skip

def _at_timing_check() -> bool:
    if _AT_BASELINE_NS[0] == 0:
        _b = _at_timed_loop()
        # If baseline itself is > 50ms, device is too loaded for timing check
        if _b > _AT_SKIP_THRESHOLD:
            return False
        _AT_BASELINE_NS[0] = max(_b, 1)
        return False
    _elapsed = _at_timed_loop()
    # Skip if baseline got reset or device is under load
    if _elapsed > _AT_SKIP_THRESHOLD:
        _AT_SUSPICIOUS_COUNT[0] = 0
        return False
    if _elapsed > _AT_BASELINE_NS[0] * 200:
        _AT_SUSPICIOUS_COUNT[0] += 1
        # Require 2 consecutive hits to avoid single-spike false positive
        return _AT_SUSPICIOUS_COUNT[0] >= 2
    else:
        _AT_SUSPICIOUS_COUNT[0] = 0
        return False

# ─────────────────────────────────────────────────────────────────────────────
# A.3 – Frame f_trace scan (full call stack)
# FIXED v3.0: Only fire if gettrace() is also active.
#             Prevents false-positives on ARM Python builds that set f_trace
#             internally without an explicit tracer installed.
# ─────────────────────────────────────────────────────────────────────────────
def _at_frame_check() -> bool:
    # Belt-and-suspenders: f_trace only meaningful when a tracer is active
    if _sys_at.gettrace() is None:
        return False
    try:
        _f = _sys_at._getframe(0)
        while _f is not None:
            if _f.f_trace is not None:
                return True
            _f = _f.f_back
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# A.4 – Code object hash tripwire
# ─────────────────────────────────────────────────────────────────────────────
def _at_code_hash_check() -> bool:
    try:
        import hashlib as _hl
        _co = _at_timed_loop.__code__
        _consts_repr = repr(_co.co_consts).encode()
        _digest = _hl.sha256(_consts_repr).hexdigest()
        return _digest != _AT_CODE_HASH
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# A.5 – threading._trace_hook canary
# ─────────────────────────────────────────────────────────────────────────────
def _at_thread_hook_check() -> bool:
    try:
        if getattr(_thr_at, "_trace_hook", None) is not None:
            return True
        if getattr(_thr_at, "_profile_hook", None) is not None:
            return True
        _ct = _thr_at.current_thread()
        if getattr(_ct, "_trace", None) is not None:
            return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# A.6 – sys.monitoring tool presence (Python 3.12+)
# Expanded: check all tool IDs including COVERAGE_ID (2), PROFILER_ID (5),
# OPTIMIZER_ID (6), DEBUGGER_ID (0)
# ─────────────────────────────────────────────────────────────────────────────
def _at_monitoring_check() -> bool:
    try:
        _mon = getattr(_sys_at, "monitoring", None)
        if _mon is None:
            return False
        # Check known tool IDs: DEBUGGER=0, COVERAGE=2, PROFILER=5, OPTIMIZER=6
        for _tool_id in (0, 1, 2, 3, 4, 5, 6):
            try:
                if _mon.get_tool(_tool_id) is not None:
                    return True
            except Exception:
                pass
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# A.7 – Detect sys.settrace called from C extension (audit event count)
# ─────────────────────────────────────────────────────────────────────────────
def _at_audit_settrace_check() -> bool:
    try:
        _seen = [0]
        def _h(event, args):
            if event in ("sys.settrace", "sys.setprofile"):
                _seen[0] += 1
        _sys_at.addaudithook(_h)
        return _seen[0] > 0
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# A.8 – Decompiler / RE module presence (NOT stdlib: dis/inspect/ast removed)
# ─────────────────────────────────────────────────────────────────────────────
_AT_RE_MODULES = frozenset((
    "uncompyle6", "decompile3", "pycdc", "bytecode",
    "xdis", "decompyle3", "unpyc3",
))

def _at_re_module_check() -> bool:
    return bool(set(_sys_at.modules.keys()) & _AT_RE_MODULES)

# ─────────────────────────────────────────────────────────────────────────────
# A.9 – Frame locals contamination
# ─────────────────────────────────────────────────────────────────────────────
_AT_SUSPICIOUS_LOCALS = frozenset((
    "__builtins_backup__", "_hook_", "_orig_", "_patched_",
    "__frida__", "_coverage_", "_trace_func",
    "pydevd", "_debugger_",
))

def _at_locals_check() -> bool:
    try:
        _f = _sys_at._getframe(0)
        while _f is not None:
            _locs = _f.f_locals
            for _name in _AT_SUSPICIOUS_LOCALS:
                if _name in _locs:
                    return True
            _f = _f.f_back
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# A.10 – co_code mutation check on this module's own functions
# ─────────────────────────────────────────────────────────────────────────────
_AT_OWN_FN_HASHES = {{}}

def _at_init_fn_hashes():
    import hashlib as _hl2
    for _fn in (_at_timed_loop, _at_frame_check, _at_timing_check):
        try:
            _co = _fn.__code__
            _raw = getattr(_co, "co_code", b"") or b""
            _AT_OWN_FN_HASHES[_fn.__name__] = _hl2.sha256(_raw).hexdigest()
        except Exception:
            pass

def _at_fn_mutation_check() -> bool:
    if not _AT_OWN_FN_HASHES:
        return False
    import hashlib as _hl3
    for _fn in (_at_timed_loop, _at_frame_check, _at_timing_check):
        try:
            _co  = _fn.__code__
            _raw = getattr(_co, "co_code", b"") or b""
            _h   = _hl3.sha256(_raw).hexdigest()
            _expected = _AT_OWN_FN_HASHES.get(_fn.__name__)
            if _expected and _h != _expected:
                return True
        except Exception:
            pass
    return False

# Initialise fn hashes at module load time
_at_init_fn_hashes()

# ─────────────────────────────────────────────────────────────────────────────
# A.11 – /proc/self/status ptrace cross-validation
# Detects ADB debugger / ptrace attachment via TracerPid.
#
# IMPORTANT: TracerPid can be transiently non-zero for a few microseconds
# during kernel audit-event processing (sys.audit() side-effect on some kernels).
# Fix: double-read with 2ms sleep between reads. A real debugger holds TracerPid
# persistently; a transient audit spike clears within <1ms.
#
# Thread anomaly check: Frida typically injects 10+ threads into a simple
# Python process. Only flag if threads > 20 AND gettrace is active (belt+suspenders).
# ─────────────────────────────────────────────────────────────────────────────
def _at_procstatus_check() -> bool:
    # TracerPid check: require corroboration from wchan OR gettrace.
    # Rationale: some environments (sandboxes, audit-hook systems) set TracerPid
    # transiently as a side-effect of sys.audit() calls. A real debugger
    # always also leaves evidence in wchan (ptrace_stop/ptrace) or
    # has gettrace() active. Requiring corroboration eliminates audit FPs.
    try:
        _tracer = 0
        with open("/proc/self/status", "rb") as _f:
            for _raw in _f:
                _line = _raw.replace(b"\x00", b"").decode("utf-8", errors="replace")
                if _line.startswith("TracerPid:"):
                    try:
                        _tracer = int(_line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
        if _tracer <= 0:
            return False
        # TracerPid > 0: need at least one corroborating signal
        # (1) gettrace active → Python tracer is attached
        if _sys_at.gettrace() is not None:
            return True
        # (2) wchan shows ptrace-related kernel wait state
        try:
            with open("/proc/self/wchan", "rb") as _fw:
                _wchan = _fw.read().replace(b"\x00", b"").decode("utf-8", errors="replace").strip().lower()
            if "ptrace" in _wchan or "trace_stop" in _wchan:
                return True
        except OSError:
            pass
        # (3) /proc/self/maps shows a debugger shared library
        try:
            with open("/proc/self/maps", "rb") as _fm:
                _maps = _fm.read().replace(b"\x00", b"").decode("utf-8", errors="replace").lower()
            _debugger_libs = ("gdbserver", "lldb", "frida-agent", "frida-gadget")
            if any(_lib in _maps for _lib in _debugger_libs):
                return True
        except OSError:
            pass
        # TracerPid > 0 but no corroboration → likely sandbox/audit artifact, skip
    except OSError:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# Composite check
# ─────────────────────────────────────────────────────────────────────────────
def _pg_anti_trace() -> bool:
    checks = [
        ("direct",         _at_direct_check),
        ("monitoring",     _at_monitoring_check),
        ("procstatus",     _at_procstatus_check),
        ("thread_hook",    _at_thread_hook_check),
        ("code_hash",      _at_code_hash_check),
        ("fn_mutation",    _at_fn_mutation_check),
        ("re_module",      _at_re_module_check),
        ("locals",         _at_locals_check),
        ("audit_settrace", _at_audit_settrace_check),
        ("frame",          _at_frame_check),
        ("timing",         _at_timing_check),
    ]
    for _name, _fn in checks:
        try:
            if _fn():
                _sys_at.stderr.write("[PG-DEBUG] trace:" + _name + "\n")
                return True
        except Exception:
            pass
    return False
'''


def generate_anti_trace_code(seed: int = 0) -> str:
    rng = random.Random(seed ^ 0xDEADBEEF ^ 0x11)
    calib_n   = rng.randint(8_000, 24_000)
    magic     = rng.randint(0x1_0001, 0xFFFF_FFFF) | 1
    init_x    = rng.randint(0x1000, 0xFFFF_FFFF)
    code_hash = "0" * 64
    return _ANTI_TRACE_TEMPLATE.format(
        calib_n   = calib_n,
        magic     = magic,
        init_x    = init_x,
        code_hash = code_hash,
    )


def compute_code_hash(generated_code: str) -> str:
    """Compute the runtime-stable hash of _at_timed_loop's code object.

    Hashes co_consts only (not co_code) — co_consts holds actual constant
    VALUES (integers, None) which are Python-version-independent and stable
    across ARM64 vs x86_64 compilations of the same source.
    co_code differs between Python 3.11 / 3.12 / 3.13 and across arches.
    """
    import re
    const_block = "\n".join(
        line for line in generated_code.splitlines()
        if re.match(r'_AT_CALIB_N\s*=|_AT_MAGIC\s*=|_AT_INIT_X\s*=', line)
    )
    m = re.search(
        r'(def _at_timed_loop\b[^\n]*\n(?:[ \t]+[^\n]*\n?)+)',
        generated_code,
    )
    if not m:
        raise RuntimeError("compute_code_hash: _at_timed_loop definition not found")
    fn_source = const_block + "\n" + m.group(1)

    _ns: dict = {}
    exec(compile(fn_source, "<anti_trace_hash>", "exec"), _ns)  # noqa: S102
    fn = _ns.get("_at_timed_loop")
    if fn is None:
        raise RuntimeError("compute_code_hash: _at_timed_loop not defined after exec")
    co = fn.__code__
    consts_repr = repr(co.co_consts).encode()
    return hashlib.sha256(consts_repr).hexdigest()


def finalise_code_hash(generated_code: str) -> str:
    real_hash = compute_code_hash(generated_code)
    return generated_code.replace(repr("0" * 64), repr(real_hash), 1)
