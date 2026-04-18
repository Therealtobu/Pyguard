"""
Stage 7 – SO Integrity Verifier (Module G)

Verifies the embedded native .so before loading it.

  G.1 – ELF magic bytes check (\x7fELF)
  G.2 – File size validation against build-time embedded expectation
  G.3 – SHA-256 hash verification (computed at build time, checked at runtime)
  G.4 – Breakpoint scan (0xCC INT3 bytes) in first 4KB of .so
  G.5 – ELF section count sanity check (too many sections = injection)
  G.6 – PT_LOAD segment permissions check (no unexpected rwx segments)

The build-time hash is embedded by stub_generator.generate_stub().
If the .so blob is absent or empty, all checks are skipped gracefully.
"""
from __future__ import annotations
import hashlib
import struct
import random


_SO_INTEGRITY_TEMPLATE = '''
import struct as _struct_si

# ── Build-time constants (set by stub_generator) ──────────────────────────────
_SI_SO_SHA256    = {so_sha256!r}   # hex SHA-256 of decrypted .so bytes
_SI_SO_MIN_SIZE  = {so_min_size}   # bytes: reject if smaller
_SI_SO_MAX_SIZE  = {so_max_size}   # bytes: reject if larger (0 = no limit)

_SI_BUILD_TAG    = {build_tag:#010x}

# ELF constants
_SI_ELF_MAGIC    = b"\\x7fELF"
_SI_PT_LOAD      = 1
_SI_PF_X         = 1
_SI_PF_W         = 2
_SI_PF_R         = 4

# ─────────────────────────────────────────────────────────────────────────────
# G.1 – ELF magic
# ─────────────────────────────────────────────────────────────────────────────
def _si_check_elf_magic(so_bytes: bytes) -> bool:
    """Returns True (fail) if magic is wrong."""
    return len(so_bytes) < 4 or so_bytes[:4] != _SI_ELF_MAGIC

# ─────────────────────────────────────────────────────────────────────────────
# G.2 – Size sanity
# ─────────────────────────────────────────────────────────────────────────────
def _si_check_size(so_bytes: bytes) -> bool:
    _n = len(so_bytes)
    if _n < _SI_SO_MIN_SIZE:
        return True
    if _SI_SO_MAX_SIZE > 0 and _n > _SI_SO_MAX_SIZE:
        return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# G.3 – SHA-256 hash
# ─────────────────────────────────────────────────────────────────────────────
def _si_check_hash(so_bytes: bytes) -> bool:
    """Returns True (fail) if hash mismatch. Skipped if sentinel hash."""
    if _SI_SO_SHA256 == "0" * 64:
        return False   # no hash embedded (build without .so)
    import hashlib as _hl_si
    _actual = _hl_si.sha256(so_bytes).hexdigest()
    return _actual != _SI_SO_SHA256

# ─────────────────────────────────────────────────────────────────────────────
# G.4 – Breakpoint scan (first 4KB)
# ─────────────────────────────────────────────────────────────────────────────
def _si_check_breakpoints(so_bytes: bytes) -> bool:
    _scan = so_bytes[:4096]
    _count_0xcc = _scan.count(0xCC)
    # 0xCC can appear in legitimate data sections — only flag dense clusters
    # More than 4 consecutive or 8 total in first 4KB is suspicious
    if _count_0xcc > 8:
        return True
    # Check for consecutive INT3 clusters (breakpoint sled)
    for _i in range(len(_scan) - 3):
        if _scan[_i] == _scan[_i+1] == _scan[_i+2] == _scan[_i+3] == 0xCC:
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# G.5 – ELF section count sanity
# ─────────────────────────────────────────────────────────────────────────────
def _si_check_section_count(so_bytes: bytes) -> bool:
    try:
        if len(so_bytes) < 64:
            return True
        _ei_class = so_bytes[4]   # 1=32-bit, 2=64-bit
        if _ei_class == 2:   # 64-bit ELF
            if len(so_bytes) < 64:
                return True
            _e_shnum = _struct_si.unpack_from("<H", so_bytes, 60)[0]
        elif _ei_class == 1:   # 32-bit ELF
            if len(so_bytes) < 52:
                return True
            _e_shnum = _struct_si.unpack_from("<H", so_bytes, 48)[0]
        else:
            return True   # unknown class
        # A shared library normally has 20-60 sections.
        # Injected sections would push this above ~100.
        if _e_shnum > 128:
            return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# G.6 – PT_LOAD segment permissions (no unexpected rwx)
# ─────────────────────────────────────────────────────────────────────────────
def _si_check_phdr_permissions(so_bytes: bytes) -> bool:
    try:
        if len(so_bytes) < 64:
            return False
        _ei_class = so_bytes[4]
        if _ei_class == 2:   # 64-bit
            _e_phoff  = _struct_si.unpack_from("<Q", so_bytes, 32)[0]
            _e_phentsize = _struct_si.unpack_from("<H", so_bytes, 54)[0]
            _e_phnum  = _struct_si.unpack_from("<H", so_bytes, 56)[0]
            for _i in range(min(_e_phnum, 32)):
                _off = _e_phoff + _i * _e_phentsize
                if _off + 56 > len(so_bytes):
                    break
                _p_type  = _struct_si.unpack_from("<I", so_bytes, _off)[0]
                _p_flags = _struct_si.unpack_from("<I", so_bytes, _off + 4)[0]
                if _p_type == _SI_PT_LOAD:
                    # RWX segment in a .so is suspicious (Frida code injection)
                    if (_p_flags & (_SI_PF_R | _SI_PF_W | _SI_PF_X)) == \
                       (_SI_PF_R | _SI_PF_W | _SI_PF_X):
                        return True
    except Exception:
        pass
    return False

# ─────────────────────────────────────────────────────────────────────────────
# G – Master SO integrity check
# ─────────────────────────────────────────────────────────────────────────────
def _pg_verify_so(so_bytes: bytes) -> bool:
    """
    Returns True if the .so is VALID and safe to load.
    Returns False and triggers _hk_die() if tampered.
    """
    if not so_bytes:
        return True   # no .so embedded — skip checks

    if _si_check_elf_magic(so_bytes):    return False
    if _si_check_size(so_bytes):         return False
    if _si_check_hash(so_bytes):         return False
    if _si_check_breakpoints(so_bytes):  return False
    if _si_check_section_count(so_bytes): return False
    if _si_check_phdr_permissions(so_bytes): return False
    return True
'''


def generate_so_integrity_code(
    seed: int = 0,
    so_sha256: str = "0" * 64,
    so_min_size: int = 1024,
    so_max_size: int = 0,
) -> str:
    """
    Generate the SO integrity runtime code block.

    Args:
        seed:         Obfuscation seed.
        so_sha256:    Hex SHA-256 of decrypted .so bytes (embed at build time).
        so_min_size:  Minimum acceptable .so size in bytes.
        so_max_size:  Maximum acceptable .so size in bytes (0 = unlimited).
    """
    rng = random.Random(seed ^ 0xB0B0B0B0 ^ 0x77)
    build_tag = rng.randint(0, 0xFFFFFFFF)
    return _SO_INTEGRITY_TEMPLATE.format(
        so_sha256   = so_sha256,
        so_min_size = so_min_size,
        so_max_size = so_max_size,
        build_tag   = build_tag,
    )


def compute_so_sha256(so_bytes: bytes) -> str:
    """Compute the SHA-256 hex digest of raw .so bytes for embedding."""
    return hashlib.sha256(so_bytes).hexdigest()
