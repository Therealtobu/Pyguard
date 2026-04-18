"""
Module 2.3 – SR-VM Bytecode Encryptor
Encrypts compiled SR-VM bytecode using AES-256-GCM.

Key derivation:
  master_key = PBKDF2(seed_bytes || build_salt, HKDF_info, 32 bytes)

Each function gets an independent nonce so ciphertexts are uncorrelated.
The authentication tag (16 bytes) detects any tampering at load time.

Encrypted bundle layout per function:
  [4 bytes: nonce_len] [nonce] [4 bytes: ct_len] [ciphertext] [16 bytes: tag]

The bundle is stored in the stage7 payload; the master_key seed is stored
separately encrypted (RSA / Locker layer) and injected at runtime.
"""

from __future__ import annotations
import os
import struct
import hashlib
import hmac
from typing import Dict, Optional

from stage2.srvm_compiler import Bytecode


# ── AES-GCM (pure-Python fallback + optional cryptography lib) ───────────────

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


def _aes_gcm_encrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Returns (ciphertext, tag). Tag is 16 bytes."""
    if _HAS_CRYPTOGRAPHY:
        aesgcm = AESGCM(key)
        ct_tag = aesgcm.encrypt(nonce, data, aad or None)
        return ct_tag[:-16], ct_tag[-16:]
    else:
        # Pure-Python AES-CTR + GHASH fallback
        from _aes_gcm_pure import encrypt as _enc  # type: ignore
        return _enc(key, nonce, data, aad)


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    if _HAS_CRYPTOGRAPHY:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, aad or None)
    else:
        from _aes_gcm_pure import decrypt as _dec  # type: ignore
        return _dec(key, nonce, ciphertext, tag, aad)


# ─────────────────────────────────────────────────────────────────────────────
# Key Derivation
# ─────────────────────────────────────────────────────────────────────────────

HKDF_INFO     = b"SRVM-BYTECODE-v1"
PBKDF2_ITERS  = 200_000
KEY_LENGTH    = 32   # AES-256


def derive_master_key(seed: bytes, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 master key derivation."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        seed + HKDF_INFO,
        salt,
        PBKDF2_ITERS,
        dklen=KEY_LENGTH,
    )


def derive_function_key(master_key: bytes, function_name: str) -> bytes:
    """Per-function subkey: HMAC(master_key, fn_name || HKDF_INFO)."""
    return hmac.new(
        master_key,
        function_name.encode() + HKDF_INFO,
        "sha256",
    ).digest()[:KEY_LENGTH]


# ─────────────────────────────────────────────────────────────────────────────
# Encrypted Bytecode Bundle
# ─────────────────────────────────────────────────────────────────────────────

class EncryptedBytecode:
    """
    Holds the encrypted result for one compiled function.
    """
    __slots__ = ("function_name", "nonce", "ciphertext", "tag",
                 "const_table", "name_table", "key_salt", "aad")

    def __init__(
        self,
        function_name: str,
        nonce:         bytes,
        ciphertext:    bytes,
        tag:           bytes,
        const_table:   list,
        name_table:    list,
        key_salt:      bytes,
        aad:           bytes = b"",
    ):
        self.function_name = function_name
        self.nonce         = nonce
        self.ciphertext    = ciphertext
        self.tag           = tag
        self.const_table   = const_table
        self.name_table    = name_table
        self.key_salt      = key_salt
        self.aad           = aad

    def serialise(self) -> bytes:
        """
        Wire format:
          [2B: name_len][name]
          [2B: salt_len][salt]
          [2B: nonce_len][nonce]
          [4B: ct_len][ciphertext]
          [16B: tag]
          [2B: aad_len][aad]
        """
        name_b  = self.function_name.encode()
        pieces  = [
            struct.pack('<H', len(name_b)), name_b,
            struct.pack('<H', len(self.key_salt)), self.key_salt,
            struct.pack('<H', len(self.nonce)), self.nonce,
            struct.pack('<I', len(self.ciphertext)), self.ciphertext,
            self.tag,                          # always 16 bytes
            struct.pack('<H', len(self.aad)), self.aad,
        ]
        return b"".join(pieces)

    @classmethod
    def deserialise(cls, data: bytes) -> "EncryptedBytecode":
        off = 0
        def rd(n):
            nonlocal off
            v = data[off:off+n]; off += n; return v

        def rd_lenprefix(width=2):
            sz = struct.unpack('<H', rd(width))[0]
            return rd(sz)

        name_b    = rd_lenprefix()
        salt      = rd_lenprefix()
        nonce     = rd_lenprefix()
        ct_sz     = struct.unpack('<I', rd(4))[0]
        ciphertext= rd(ct_sz)
        tag       = rd(16)
        aad       = rd_lenprefix()
        return cls(
            function_name = name_b.decode(),
            nonce         = nonce,
            ciphertext    = ciphertext,
            tag           = tag,
            const_table   = [],
            name_table    = [],
            key_salt      = salt,
            aad           = aad,
        )

    def decrypt(self, master_key: bytes) -> bytes:
        fn_key = derive_function_key(master_key, self.function_name)
        return _aes_gcm_decrypt(fn_key, self.nonce, self.ciphertext, self.tag, self.aad)


# ─────────────────────────────────────────────────────────────────────────────
# Bytecode Encryptor
# ─────────────────────────────────────────────────────────────────────────────

class BytecodeEncryptor:
    """
    Encrypts a dict of {function_name: Bytecode} with AES-256-GCM.
    Each function gets:
      • Independent random nonce (12 bytes)
      • Independent salt for key derivation
      • AAD = function_name + build_fingerprint
    """

    NONCE_SIZE = 12  # GCM standard
    SALT_SIZE  = 16

    def __init__(self, master_key: bytes, build_fingerprint: bytes = b""):
        self._master_key       = master_key
        self._build_fingerprint = build_fingerprint

    @classmethod
    def from_seed(cls, seed: bytes, build_salt: Optional[bytes] = None) -> "BytecodeEncryptor":
        if build_salt is None:
            build_salt = os.urandom(16)
        master_key = derive_master_key(seed, build_salt)
        return cls(master_key, build_fingerprint=build_salt)

    # ── main API ─────────────────────────────────────────────────────────────

    def encrypt_all(
        self,
        bytecodes: Dict[str, Bytecode],
    ) -> Dict[str, EncryptedBytecode]:
        results = {}
        for fn_name, bc in bytecodes.items():
            results[fn_name] = self._encrypt_one(fn_name, bc)
        return results

    def decrypt_all(
        self,
        encrypted: Dict[str, EncryptedBytecode],
    ) -> Dict[str, bytes]:
        results = {}
        for fn_name, enc in encrypted.items():
            results[fn_name] = enc.decrypt(self._master_key)
        return results

    # ── internal ─────────────────────────────────────────────────────────────

    def _encrypt_one(self, fn_name: str, bc: Bytecode) -> EncryptedBytecode:
        nonce    = os.urandom(self.NONCE_SIZE)
        key_salt = os.urandom(self.SALT_SIZE)
        fn_key   = derive_function_key(self._master_key, fn_name)
        aad      = fn_name.encode() + self._build_fingerprint

        raw_bc   = bc.bytes()
        ct, tag  = _aes_gcm_encrypt(fn_key, nonce, raw_bc, aad)

        return EncryptedBytecode(
            function_name = fn_name,
            nonce         = nonce,
            ciphertext    = ct,
            tag           = tag,
            const_table   = list(bc.const_table),
            name_table    = list(bc.name_table),
            key_salt      = key_salt,
            aad           = aad,
        )

    # ── serialise all ────────────────────────────────────────────────────────

    def serialise_bundle(self, encrypted: Dict[str, EncryptedBytecode]) -> bytes:
        """
        Bundle format:
          [4B: magic] [2B: n_funcs]
          for each: [4B: entry_len] [entry_bytes]
        """
        MAGIC = b"SRVC"
        pieces = [MAGIC, struct.pack('<H', len(encrypted))]
        for enc in encrypted.values():
            entry = enc.serialise()
            pieces.append(struct.pack('<I', len(entry)))
            pieces.append(entry)
        return b"".join(pieces)

    @staticmethod
    def deserialise_bundle(data: bytes) -> Dict[str, EncryptedBytecode]:
        MAGIC = b"SRVC"
        off   = 0
        assert data[:4] == MAGIC, "Invalid SRVM bundle magic"
        off += 4
        n = struct.unpack('<H', data[off:off+2])[0]; off += 2
        result = {}
        for _ in range(n):
            sz  = struct.unpack('<I', data[off:off+4])[0]; off += 4
            enc = EncryptedBytecode.deserialise(data[off:off+sz]); off += sz
            result[enc.function_name] = enc
        return result


# ─── convenience ─────────────────────────────────────────────────────────────

def encrypt_bytecodes(
    bytecodes: Dict[str, Bytecode],
    seed: Optional[bytes] = None,
) -> tuple[Dict[str, EncryptedBytecode], bytes]:
    """
    Returns (encrypted_dict, master_key_seed).
    master_key_seed must be stored securely in the payload header.
    """
    if seed is None:
        seed = os.urandom(32)
    enc = BytecodeEncryptor.from_seed(seed)
    encrypted = enc.encrypt_all(bytecodes)
    return encrypted, seed
