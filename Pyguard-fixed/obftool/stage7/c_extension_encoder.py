"""
Module 7.5 – C Extension Encoder
Encodes the compiled .so (or the payload envelope) to base64 chunks
suitable for embedding in a Python source file as string literals.

Also encrypts the .so blob with AES-256-GCM using the graph_master_key
so that the embedded binary is not directly readable from the stub.
"""
from __future__ import annotations
import base64
import os
import textwrap
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SO_AAD = b"PyGuard-V1-SO-Blob"


def _derive_so_key(graph_master_key: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", graph_master_key, b"PYGUARD-SO-KEY-V1", 100_000, dklen=32
    )


def encrypt_and_encode_so(so_bytes: bytes, graph_master_key: bytes) -> tuple[str, str]:
    """
    Encrypt the .so blob and return:
      (b64_ciphertext, so_key_hex)
    """
    so_key  = _derive_so_key(graph_master_key)
    nonce   = os.urandom(12)
    aesgcm  = AESGCM(so_key)
    ct      = aesgcm.encrypt(nonce, so_bytes, _SO_AAD)
    blob    = nonce + ct          # 12-byte nonce prefix
    return base64.b64encode(blob).decode(), so_key.hex()


def decrypt_so(b64_blob: str, so_key_hex: str) -> bytes:
    """Inverse – used by the Python stub loader at runtime."""
    so_key  = bytes.fromhex(so_key_hex)
    raw     = base64.b64decode(b64_blob)
    nonce   = raw[:12]
    ct      = raw[12:]
    aesgcm  = AESGCM(so_key)
    return aesgcm.decrypt(nonce, ct, _SO_AAD)


def encode_payload(envelope_bytes: bytes) -> str:
    """Simple base64 encode for the outer payload envelope."""
    return base64.b64encode(envelope_bytes).decode()


def chunk_b64(b64_str: str, width: int = 76) -> str:
    """Split a long base64 string into a Python multi-line string literal."""
    lines  = textwrap.wrap(b64_str, width)
    joined = "\n".join(f'    "{line}"' for line in lines)
    return "(\n" + joined + "\n)"
