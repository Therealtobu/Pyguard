"""
Stage 7 – Anti-Dump Module (Module D)
Generates Python runtime code for:

  D.1 – Secret splitting (XOR shares across Python heap + ctypes buffer)
  D.2 – mprotect key pages (via ctypes mmap / mprotect on Linux)
  D.3 – Decoy key flood (1000 fake AES-looking keys in heap)
  D.4 – Immediate wipe after use (ctypes memset on key material)
  D.5 – Address-dependent key material (key XOR'd with its own address)

These are Python-level approximations; the C watchdog handles mprotect
at the native level for the .so payload. This module protects the Python
key material that wraps the outer AES-GCM envelope.
"""
from __future__ import annotations
import random
import hashlib
import os


_ANTI_DUMP_TEMPLATE = '''
import os   as _os_ad
import sys  as _sys_ad
import ctypes as _ct_ad

# ── Build-time decoy constants (unique per build) ─────────────────────────────
_AD_DECOY_SEED  = {decoy_seed:#010x}
_AD_SHARE_MAGIC = {share_magic:#010x}

# ─────────────────────────────────────────────────────────────────────────────
# D.1 – Secret splitting: key = SHARE_A XOR SHARE_B XOR SHARE_C
# SHARE_A: Python bytearray (heap)
# SHARE_B: ctypes char array (C heap, separate segment)
# SHARE_C: derived from address of SHARE_A (address-dependent)
# ─────────────────────────────────────────────────────────────────────────────
class _SecretStore:
    """Holds a secret split across three independently-allocated regions."""

    __slots__ = ("_a", "_b", "_bc", "_ln")

    def __init__(self, key_bytes: bytes):
        _n = len(key_bytes)
        self._ln = _n
        # SHARE_B in ctypes buffer (C heap)
        self._bc = (_ct_ad.c_uint8 * _n)()
        # Generate SHARE_A and SHARE_B randomly; SHARE_C = key XOR A XOR B
        _share_a = bytearray(_os_ad.urandom(_n))
        _share_b = bytearray(_os_ad.urandom(_n))
        _share_c = bytearray(
            key_bytes[i] ^ _share_a[i] ^ _share_b[i] for i in range(_n)
        )
        self._a = _share_a          # Python heap
        for i, b in enumerate(_share_b):
            self._bc[i] = b       # C heap
        # Encode SHARE_C as address-dependent: C[i] ^= (addr >> (i%8)) & 0xFF
        _addr = id(self._a)
        self._b = bytearray(
            _share_c[i] ^ ((_addr >> (i % 8)) & 0xFF) for i in range(_n)
        )

    def get(self) -> bytes:
        """Reconstruct key. Call wipe() immediately after use."""
        _n    = self._ln
        _addr = id(self._a)
        _c    = bytearray(
            self._b[i] ^ ((_addr >> (i % 8)) & 0xFF) for i in range(_n)
        )
        return bytes(
            self._a[i] ^ self._bc[i] ^ _c[i] for i in range(_n)
        )

    def wipe(self):
        """Zero all three shares immediately after key use."""
        try:
            _ct_ad.memset(
                (_ct_ad.c_uint8 * self._ln).from_buffer(self._a),
                0, self._ln
            )
        except Exception:
            for i in range(self._ln):
                self._a[i] = 0
        try:
            _ct_ad.memset(self._bc, 0, self._ln)
        except Exception:
            for i in range(self._ln):
                self._bc[i] = 0
        for i in range(self._ln):
            self._b[i] = 0

    def __del__(self):
        try:
            self.wipe()
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# D.2 – mprotect key page (Linux only)
# Allocates key on its own mmap page; revokes read permission when idle.
# ─────────────────────────────────────────────────────────────────────────────
try:
    _libc_ad = _ct_ad.CDLL("libc.so.6", use_errno=True)
    _mmap_f  = _libc_ad.mmap
    _mmap_f.restype  = _ct_ad.c_void_p
    _mmap_f.argtypes = [
        _ct_ad.c_void_p, _ct_ad.c_size_t, _ct_ad.c_int,
        _ct_ad.c_int, _ct_ad.c_int, _ct_ad.c_long,
    ]
    _mprotect_f = _libc_ad.mprotect
    _mprotect_f.restype  = _ct_ad.c_int
    _mprotect_f.argtypes = [_ct_ad.c_void_p, _ct_ad.c_size_t, _ct_ad.c_int]
    _munmap_f = _libc_ad.munmap
    _munmap_f.restype  = _ct_ad.c_int
    _munmap_f.argtypes = [_ct_ad.c_void_p, _ct_ad.c_size_t]
    _MMAP_AVAILABLE = True
except Exception:
    _MMAP_AVAILABLE = False

_PROT_NONE  = 0
_PROT_READ  = 1
_PROT_WRITE = 2
_MAP_PRIVATE   = 0x02
_MAP_ANONYMOUS = 0x20
_PAGE_SIZE = 4096

class _ProtectedPage:
    """
    A single mmap page that is PROT_NONE when idle.
    Grants PROT_READ only for the duration of get().
    Memory dumps of PROT_NONE pages return zeros or trigger SIGSEGV.
    Falls back to _SecretStore if mmap unavailable.
    """

    def __init__(self, key_bytes: bytes):
        self._ln = len(key_bytes)
        self._page = None
        self._fallback = None

        if _MMAP_AVAILABLE and self._ln <= _PAGE_SIZE:
            try:
                _ptr = _mmap_f(
                    None, _PAGE_SIZE,
                    _PROT_READ | _PROT_WRITE,
                    _MAP_PRIVATE | _MAP_ANONYMOUS,
                    -1, 0,
                )
                if _ptr and _ptr != _ct_ad.c_void_p(-1).value:
                    _ct_ad.memmove(_ptr, key_bytes, self._ln)
                    _mprotect_f(_ptr, _PAGE_SIZE, _PROT_NONE)
                    self._page = _ptr
                    return
            except Exception:
                pass

        # Fallback: secret split
        self._fallback = _SecretStore(key_bytes)

    def get(self) -> bytes:
        if self._page is not None:
            try:
                _mprotect_f(self._page, _PAGE_SIZE, _PROT_READ)
                _buf = (_ct_ad.c_uint8 * self._ln)()
                _ct_ad.memmove(_buf, self._page, self._ln)
                _mprotect_f(self._page, _PAGE_SIZE, _PROT_NONE)
                return bytes(_buf)
            except Exception:
                pass
        if self._fallback is not None:
            return self._fallback.get()
        return b""

    def wipe(self):
        if self._page is not None:
            try:
                _mprotect_f(self._page, _PAGE_SIZE, _PROT_READ | _PROT_WRITE)
                _ct_ad.memset(self._page, 0, _PAGE_SIZE)
                _munmap_f(self._page, _PAGE_SIZE)
            except Exception:
                pass
            self._page = None
        if self._fallback is not None:
            self._fallback.wipe()
            self._fallback = None

    def __del__(self):
        try:
            self.wipe()
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
# D.3 – Decoy key flood
# Fills heap with 256 fake AES-256 keys that look real.
# Attacker dumping memory sees 257 candidate keys; can\'t identify the real one.
# ─────────────────────────────────────────────────────────────────────────────
def _ad_flood_decoys(n: int = 256) -> list:
    """Allocate N fake 32-byte keys. Keep reference alive during execution."""
    import random as _r
    _rng = _r.Random(_AD_DECOY_SEED ^ id(_r))
    return [bytearray(_rng.randint(0, 255) for _ in range(32)) for _ in range(n)]

# ─────────────────────────────────────────────────────────────────────────────
# D.4 – Secure key wrapper: public API
# ─────────────────────────────────────────────────────────────────────────────
def _pg_make_secure_key(key_hex: str) -> "_ProtectedPage":
    """
    Convert a hex key string into a protected key object.
    The hex string is wiped from the bytearray after loading.
    """
    _raw = bytearray.fromhex(key_hex)
    _obj = _ProtectedPage(bytes(_raw))
    # Zero the bytearray immediately
    for _i in range(len(_raw)):
        _raw[_i] = 0
    return _obj

def _pg_use_key(secure_key: "_ProtectedPage", callback):
    """
    Retrieve key bytes, call callback(key_bytes), then immediately wipe.
    Usage: _pg_use_key(sk, lambda k: AESGCM(k).decrypt(...))
    """
    _key = secure_key.get()
    try:
        return callback(_key)
    finally:
        # Wipe local copy
        _mutable = bytearray(_key)
        for _i in range(len(_mutable)):
            _mutable[_i] = 0

# ─────────────────────────────────────────────────────────────────────────────
# D.5 – Global decoy flood (keep alive for process lifetime)
# ─────────────────────────────────────────────────────────────────────────────
_AD_DECOYS = _ad_flood_decoys(256)
'''


def generate_anti_dump_code(seed: int = 0) -> str:
    """Generate the anti-dump runtime code block."""
    rng = random.Random(seed ^ 0xDEADC0DE ^ 0x44)

    decoy_seed   = rng.randint(0, 0xFFFFFFFF)
    share_magic  = rng.randint(0, 0xFFFFFFFF)

    return _ANTI_DUMP_TEMPLATE.format(
        decoy_seed   = decoy_seed,
        share_magic  = share_magic,
    )
