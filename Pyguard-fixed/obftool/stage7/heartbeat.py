"""
Stage 7 – Heartbeat / Background Integrity Thread (Module H)

Spawns a hidden daemon thread that continuously re-runs anti-debug,
anti-trace, and anti-hook checks AFTER the initial startup scan.

This catches tools like Frida that attach AFTER the process starts,
or dynamic patchers that activate mid-execution.

  H.1 – Daemon thread with randomized check interval (3–8 s, jittered)
  H.2 – Thread name disguised as a GC/maintenance worker
  H.3 – Re-runs _pg_anti_debug(), _pg_anti_trace(), _pg_anti_hook()
  H.4 – Re-runs _pg_anti_vm() for late-attach sandbox detection
  H.5 – Checks /proc/self/maps for new Frida agent mappings each cycle
  H.6 – Monitors sys.settrace / sys.gettrace for late injection
  H.7 – Validates that _pg_anti_debug / _pg_anti_trace code objects
         have not been replaced (checks __code__.co_firstlineno)
  H.8 – Corruption guard: if heartbeat thread dies unexpectedly,
         main thread detects absence on next opportunistic check

Thread intentionally does NOT print; just plants canary + self-destructs
+ aborts to avoid giving attacker time to react.
"""
from __future__ import annotations
import random


_HEARTBEAT_TEMPLATE = '''
import threading as _thr_hb
import time      as _time_hb
import os        as _os_hb
import sys       as _sys_hb

# ── Build-time constants ──────────────────────────────────────────────────────
_HB_MIN_INTERVAL = {min_interval}    # seconds
_HB_MAX_INTERVAL = {max_interval}    # seconds
_HB_BUILD_NONCE  = {build_nonce:#010x}

# Disguised thread name pool
_HB_THREAD_NAMES = (
    "_gc_finalize",
    "_mem_compactor",
    "_ref_cycle_gc",
    "_timer_wheel",
    "_cache_evict",
    "_sched_idle",
)

# ─────────────────────────────────────────────────────────────────────────────
# H.7 – Code object guardian: record co_firstlineno of each check fn at startup
# If the fn is replaced later, co_firstlineno changes → detected.
# ─────────────────────────────────────────────────────────────────────────────
_HB_SENTINEL = {{}}

def _hb_record_sentinels():
    try:
        _HB_SENTINEL["anti_debug"] = _pg_anti_debug.__code__.co_firstlineno
        _HB_SENTINEL["anti_trace"] = _pg_anti_trace.__code__.co_firstlineno
        _HB_SENTINEL["anti_hook"]  = _pg_anti_hook.__code__.co_firstlineno
        _HB_SENTINEL["anti_vm"]    = _pg_anti_vm.__code__.co_firstlineno
    except Exception:
        pass

def _hb_check_sentinels() -> bool:
    try:
        if _pg_anti_debug.__code__.co_firstlineno != _HB_SENTINEL.get("anti_debug"):
            return True
        if _pg_anti_trace.__code__.co_firstlineno != _HB_SENTINEL.get("anti_trace"):
            return True
        if _pg_anti_hook.__code__.co_firstlineno != _HB_SENTINEL.get("anti_hook"):
            return True
        if _pg_anti_vm.__code__.co_firstlineno != _HB_SENTINEL.get("anti_vm"):
            return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# H.5 – Late Frida map scan (check for new rwx anonymous pages)
# ─────────────────────────────────────────────────────────────────────────────
def _hb_check_maps_late() -> bool:
    try:
        with open("/proc/self/maps", "r") as _f:
            _maps = _f.read().lower()
        _frida_hot = ("frida-agent", "frida-gadget", "gum-js-loop",
                      "__frida", "frida-core")
        for _m in _frida_hot:
            if _m in _maps:
                return True
        # Large anonymous rwx pages added after startup → Frida code arena
        for _line in _maps.splitlines():
            _p = _line.split()
            if len(_p) >= 6 and _p[1] == "rwxp" and _p[5] == "":
                try:
                    _s, _e = _p[0].split("-")
                    if int(_e, 16) - int(_s, 16) >= 0x8000:
                        return True
                except Exception:
                    pass
    except OSError:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# H.6 – Late sys.settrace / sys.gettrace check
# ─────────────────────────────────────────────────────────────────────────────
def _hb_check_trace_late() -> bool:
    return (_sys_hb.gettrace() is not None or
            _sys_hb.getprofile() is not None)

# ─────────────────────────────────────────────────────────────────────────────
# H.3 – Silent terminate on detection
# (No print — gives attacker zero reaction time)
# ─────────────────────────────────────────────────────────────────────────────
def _hb_terminate():
    try:
        _pg_plant_canary()
    except Exception:
        pass
    try:
        _pg_self_destruct()
    except Exception:
        pass
    _os_hb.abort()

# ─────────────────────────────────────────────────────────────────────────────
# H.8 – Liveness token (main thread can check heartbeat is still alive)
# ─────────────────────────────────────────────────────────────────────────────
_HB_ALIVE = [False]   # set to True when thread starts, False on exit
_HB_LAST_BEAT = [0.0]

def _hb_is_alive_check() -> bool:
    """
    Returns True (FAIL) if heartbeat was started but has been silent
    for more than 3× the max interval. Attacker may have killed the thread.
    """
    if not _HB_ALIVE[0]:
        return False   # thread not started yet
    _elapsed = _time_hb.monotonic() - _HB_LAST_BEAT[0]
    return _elapsed > (_HB_MAX_INTERVAL * 3 + 5)

# ─────────────────────────────────────────────────────────────────────────────
# Heartbeat loop
# ─────────────────────────────────────────────────────────────────────────────
def _hb_loop():
    _HB_ALIVE[0] = True
    _rng = __import__("random").Random(_HB_BUILD_NONCE ^ __import__("os").getpid())
    try:
        while True:
            _interval = _rng.uniform(_HB_MIN_INTERVAL, _HB_MAX_INTERVAL)
            _time_hb.sleep(_interval)
            _HB_LAST_BEAT[0] = _time_hb.monotonic()

            # Stagger checks to avoid a periodic fingerprint
            _checks = [
                _pg_anti_debug,
                _pg_anti_trace,
                _pg_anti_hook,
                _pg_anti_vm,
                _hb_check_maps_late,
                _hb_check_trace_late,
                _hb_check_sentinels,
            ]
            _rng.shuffle(_checks)
            for _fn in _checks:
                try:
                    if _fn():
                        _hb_terminate()
                        return
                except Exception:
                    pass
    finally:
        _HB_ALIVE[0] = False

# ─────────────────────────────────────────────────────────────────────────────
# Public API: call from _pg_main() after all check functions are defined
# ─────────────────────────────────────────────────────────────────────────────
def _pg_heartbeat_start():
    """Start the background integrity watchdog thread."""
    _hb_record_sentinels()
    _HB_LAST_BEAT[0] = _time_hb.monotonic()
    _t = _thr_hb.Thread(target=_hb_loop, daemon=True)
    _t.name = _HB_THREAD_NAMES[_HB_BUILD_NONCE % len(_HB_THREAD_NAMES)]
    _t.start()

def _pg_heartbeat_check():
    """
    Opportunistic liveness check — call from _pg_main() after heavy work.
    If heartbeat thread was killed, terminate immediately.
    """
    if _hb_is_alive_check():
        _hb_terminate()
'''


def generate_heartbeat_code(seed: int = 0) -> str:
    """Generate the heartbeat daemon thread runtime code block."""
    rng = random.Random(seed ^ 0xABABABAB ^ 0x88)
    min_interval = round(rng.uniform(2.5, 4.0), 1)
    max_interval = round(min_interval + rng.uniform(2.0, 4.5), 1)
    build_nonce  = rng.randint(0, 0xFFFFFFFF)
    return _HEARTBEAT_TEMPLATE.format(
        min_interval = min_interval,
        max_interval = max_interval,
        build_nonce  = build_nonce,
    )
