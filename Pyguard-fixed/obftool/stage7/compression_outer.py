"""
Module 7.2 – Compression & Outer Encryption
Compresses the packed payload (zlib level-9) then wraps it in AES-256-GCM.

Wire format of the outer envelope:
  [4B  magic   ]  b'PGE1'   (PyGuard Envelope v1)
  [12B nonce   ]  AES-GCM nonce
  [16B tag     ]  AES-GCM authentication tag
  [4B  comp_len]  u32 length of compressed payload (before encryption)
  [*   ciphertext]  encrypted compressed payload
"""
from __future__ import annotations
import os
import zlib
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_MAGIC = b"PGE1"
_AAD           = b"PyGuard-V1-Outer-Envelope"


def derive_outer_key(graph_master_key: bytes, bc_seed: bytes) -> bytes:
    """Derive a 32-byte AES key from pipeline secrets."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        graph_master_key + bc_seed,
        b"PYGUARD-OUTER-KEY-V1",
        100_000,
        dklen=32,
    )


class OuterEnvelope:
    def __init__(self, nonce: bytes, tag: bytes, comp_len: int, ciphertext: bytes):
        self.nonce      = nonce
        self.tag        = tag
        self.comp_len   = comp_len
        self.ciphertext = ciphertext

    def serialise(self) -> bytes:
        return (
            ENVELOPE_MAGIC
            + self.nonce
            + self.tag
            + struct.pack("<I", self.comp_len)
            + self.ciphertext
        )

    @property
    def total_size(self) -> int:
        return 4 + 12 + 16 + 4 + len(self.ciphertext)


def compress_and_encrypt(packed_bytes: bytes, outer_key: bytes) -> OuterEnvelope:
    """
    1. zlib compress
    2. AES-256-GCM encrypt; the GCM tag is extracted from the end of the
       cryptography output (last 16 bytes) and stored separately in the header.
    """
    compressed = zlib.compress(packed_bytes, level=9)
    nonce      = os.urandom(12)
    aesgcm     = AESGCM(outer_key)
    ct_with_tag = aesgcm.encrypt(nonce, compressed, _AAD)
    # cryptography appends 16-byte tag at the end
    ciphertext  = ct_with_tag[:-16]
    tag         = ct_with_tag[-16:]
    return OuterEnvelope(nonce, tag, len(compressed), ciphertext)


def decrypt_and_decompress(envelope_bytes: bytes, outer_key: bytes) -> bytes:
    """Inverse of compress_and_encrypt (used by the Python stub loader)."""
    assert envelope_bytes[:4] == ENVELOPE_MAGIC, "Bad envelope magic"
    nonce      = envelope_bytes[4:16]
    tag        = envelope_bytes[16:32]
    comp_len   = struct.unpack_from("<I", envelope_bytes, 32)[0]
    ciphertext = envelope_bytes[36:]
    aesgcm     = AESGCM(outer_key)
    compressed = aesgcm.decrypt(nonce, ciphertext + tag, _AAD)
    assert len(compressed) == comp_len, "Decompressed size mismatch"
    return zlib.decompress(compressed)
