"""
Stage 7 – Anti-Replay Module (Module B)  [Termux-aware revision]
Generates Python runtime code for:

  B.1 – Polymorphic base32 canary file system
  B.2 – Silent self-destruct (junk overwrite that keeps obf appearance)
  B.3 – Hardware fingerprint binding
  B.4 – Execution entropy injection

FIX: Canary TTL (Time-To-Live) system.
  Previous behaviour: any detection (including false-positives) plants a canary
  → every subsequent run aborts immediately at step 0 — permanent death spiral.

  Fix: The canary payload now embeds a write timestamp (8 bytes, little-endian
  Unix seconds). _pg_canary_check() reads the timestamp and treats the canary
  as STALE if it is older than _AR_CANARY_TTL_S seconds (default 90 s).
  A stale canary is silently deleted without triggering abort.

  This means: if a false-positive happens once → canary is planted → next run
  within 90 s detects it (real tamper window) → after 90 s, canary expires and
  script runs normally again.

  A real attacker who replays the script after > 90 s still gets caught by all
  OTHER checks (A/C/D modules + integrity hash). The canary specifically catches
  the "run-immediately-after-tamper" replay window, which is preserved.

FIX 2: Canary dirs updated to include Termux-compatible paths.
"""
from __future__ import annotations
import hashlib
import random
import os


_CANARY_DIRS = [
    "~/.cache/systemd/private",
    "~/.local/share/gvfs-metadata",
    "~/.cache/dconf",
    "~/.local/share/recently-used.d",
    # Termux-compatible fallback paths
    "~/.cache/.pg",
    "~/.local/share/.pg",
]


def _pick_canary_dir(seed: int) -> str:
    return random.Random(seed).choice(_CANARY_DIRS)


_ANTI_REPLAY_CODE = r'''
import os   as _os_ar
import sys  as _sys_ar
import hmac as _hmac_ar
import hashlib as _hl_ar
import base64  as _b64_ar
import random  as _rnd_ar
import time    as _time_ar
import struct  as _struct_ar

_AR_CANARY_DIR  = @@CANARY_DIR@@
_AR_CANARY_KEY  = bytes.fromhex(@@CANARY_KEY@@)
_AR_BUILD_SALT  = @@BUILD_SALT@@
_AR_CANARY_TTL_S = 90    # seconds: canary expires after this → stale, not abort

def _ar_machine_id() -> bytes:
    _parts = []
    try:
        with open('/etc/machine-id', 'r') as _f:
            _parts.append(_f.read().strip())
    except Exception:
        pass
    try:
        with open('/proc/cpuinfo', 'r') as _f:
            for _line in _f:
                if 'model name' in _line.lower() or 'hardware' in _line.lower():
                    _parts.append(_line.split(':', 1)[-1].strip())
                    break
    except Exception:
        pass
    # Android: use /proc/sys/kernel/hostname as additional fingerprint
    try:
        with open('/proc/sys/kernel/hostname', 'r') as _f:
            _parts.append(_f.read().strip())
    except Exception:
        pass
    _raw = '|'.join(_parts) or 'unknown'
    return _hl_ar.sha256((_raw + _AR_BUILD_SALT).encode()).digest()

def _ar_new_canary_name() -> str:
    _mid  = _ar_machine_id()
    _salt = _os_ar.urandom(12)
    _h    = _hl_ar.sha256(_mid + _salt).digest()[:10]
    return _b64_ar.b32encode(_h).decode().lower().rstrip('=')

def _ar_canary_dir_path() -> str:
    return _os_ar.path.expanduser(_AR_CANARY_DIR)

def _ar_is_canary_name(name: str) -> bool:
    _B32 = set('abcdefghijklmnopqrstuvwxyz234567')
    return len(name) == 16 and all(c in _B32 for c in name)

def _ar_find_canary():
    _d = _ar_canary_dir_path()
    if not _os_ar.path.isdir(_d):
        return None, None
    try:
        for _name in _os_ar.listdir(_d):
            if _ar_is_canary_name(_name):
                _path = _os_ar.path.join(_d, _name)
                if _os_ar.path.isfile(_path):
                    return _path, _name
    except Exception:
        pass
    return None, None

def _ar_read_canary(path: str):
    """
    Returns (valid: bool, age_seconds: float).
    Payload format: [32 mac][8 timestamp_le][machine_id][16 random]
    FIX: timestamp now embedded so we can detect stale canaries.
    """
    try:
        with open(path, 'rb') as _f:
            _data = _f.read()
        if len(_data) < 40:
            return False, 999999.0
        _stored_mac = _data[:32]
        _payload    = _data[32:]
        _expected   = _hmac_ar.new(_AR_CANARY_KEY, _payload, 'sha256').digest()
        if not _hmac_ar.compare_digest(_stored_mac, _expected):
            return False, 999999.0
        # Extract timestamp (first 8 bytes of payload, little-endian)
        _ts = _struct_ar.unpack_from('<Q', _payload, 0)[0]
        _age = _time_ar.time() - _ts
        return True, _age
    except Exception:
        return False, 999999.0

def _ar_write_canary(name: str):
    _d = _ar_canary_dir_path()
    try:
        _os_ar.makedirs(_d, exist_ok=True)
        _ts      = _struct_ar.pack('<Q', int(_time_ar.time()))
        _payload = _ts + _ar_machine_id() + _os_ar.urandom(16)
        _mac     = _hmac_ar.new(_AR_CANARY_KEY, _payload, 'sha256').digest()
        _path    = _os_ar.path.join(_d, name)
        with open(_path, 'wb') as _f:
            _f.write(_mac + _payload)
        try:
            _os_ar.chmod(_path, 0o600)
        except Exception:
            pass
    except Exception:
        pass

def _ar_rename_canary(old_path: str):
    try:
        _new_name = _ar_new_canary_name()
        _new_path = _os_ar.path.join(_ar_canary_dir_path(), _new_name)
        _os_ar.rename(old_path, _new_path)
    except Exception:
        try:
            _os_ar.unlink(old_path)
        except Exception:
            pass

def _ar_delete_canary(path: str):
    try:
        _os_ar.unlink(path)
    except Exception:
        pass

def _ar_self_destruct():
    try:
        _target = __file__
        if not _target or not _os_ar.path.isfile(_target):
            return
        _mid = _ar_machine_id()
        _rng = _rnd_ar.Random(int.from_bytes(_mid[:4], 'little'))
        _jhl = _hl_ar
        _jb64 = _b64_ar
        _lines = [
            '# Protected by Pyguard V1',
            '# ' + '-'*67,
            '# WARNING: This file is protected by PyGuard.',
            '# Any modification, hooking, or reverse engineering is prohibited.',
            '# Tampering with this file will cause it to cease functioning.',
            '# ' + '-'*67,
            'import sys,os,base64,hashlib,struct,importlib.util,tempfile',
        ]
        for _ji in range(60):
            _vn = '_' + _jhl.sha256(('j' + str(_ji) + str(_rng.random())).encode()).hexdigest()[:10]
            _vv = _rng.randint(0, 0xFFFFFFFF)
            _lines.append(_vn + ' = ' + hex(_vv))
        _fake = _jb64.b64encode(bytes(_rng.randint(0, 255) for _ in range(768))).decode()
        _lines.append('_PG_SO_B64 = (')
        for _ci in range(0, len(_fake), 64):
            _lines.append('    "' + _fake[_ci:_ci+64] + '"')
        _lines.append(')')
        _lines.append('_PG_PL_KEY = "' + bytes(_rng.randint(0,255) for _ in range(32)).hex() + '"')
        _lines.append('_PG_IHASH  = "' + _jhl.sha256(b'junk').hexdigest() + '"')
        _lines.append('def _pg_main():')
        _lines.append('    raise SystemExit(0)')
        _lines.append('_pg_main()')
        _junk = '\n'.join(_lines) + '\n'
        with open(_target, 'w', encoding='utf-8') as _wf:
            _wf.write(_junk)
    except Exception:
        pass

def _pg_canary_check():
    """
    Call at startup.
    FIX: Canaries now have TTL (_AR_CANARY_TTL_S seconds).
         Stale canary (age > TTL) = silent delete, no abort.
         Fresh canary (age <= TTL) = genuine replay → abort.
    This breaks the false-positive death spiral while preserving anti-replay
    protection within the relevant tamper window.
    """
    _path, _name = _ar_find_canary()
    if _path is None:
        return
    _valid, _age = _ar_read_canary(_path)
    if not _valid:
        # Corrupt canary — delete silently (not our plant)
        _ar_delete_canary(_path)
        return
    if _age > _AR_CANARY_TTL_S:
        # Stale canary — might be from a previous false-positive run
        # Delete silently and allow execution to continue
        _ar_delete_canary(_path)
        return
    # Fresh valid canary: tamper detected within the replay window → abort
    _sys_ar.stderr.write("Stop hooking and editing the script.\n")
    _ar_rename_canary(_path)
    _ar_self_destruct()
    _os_ar.abort()

def _pg_plant_canary():
    """Plant canary file when tamper is detected (caught on next run within TTL)."""
    _name = _ar_new_canary_name()
    _ar_write_canary(_name)

def _pg_self_destruct():
    _ar_self_destruct()

def _pg_run_nonce() -> bytes:
    _ts  = int(_time_ar.perf_counter_ns()).to_bytes(8, 'little')
    _pid = str(_os_ar.getpid()).encode()
    _rnd = _os_ar.urandom(8)
    _mid = _ar_machine_id()
    return _hl_ar.sha256(_ts + _pid + _rnd + _mid).digest()
'''


def generate_anti_replay_code(seed: int = 0) -> str:
    rng = random.Random(seed ^ 0xCAFEBABE ^ 0x22)

    canary_dir  = _pick_canary_dir(seed)
    canary_key  = os.urandom(32).hex()
    build_salt  = hashlib.sha256(
        str(seed ^ rng.randint(0, 0xFFFFFFFF)).encode()
    ).hexdigest()[:16]

    return (_ANTI_REPLAY_CODE
        .replace("@@CANARY_DIR@@",  repr(canary_dir))
        .replace("@@CANARY_KEY@@",  repr(canary_key))
        .replace("@@BUILD_SALT@@",  repr(build_salt)))
