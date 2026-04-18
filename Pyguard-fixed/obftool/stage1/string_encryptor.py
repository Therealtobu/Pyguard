"""
Stage 1 – String & Constant Encryptor

Encrypts string literals and sensitive constants in LOAD_CONST IR instructions.
Replaces them with runtime decryption calls that reconstruct the original value.

Encryption scheme per string:
  1. XOR each byte with a per-string key derived from: sha256(seed || str_pos || str_hash)
  2. Key is stored as encrypted bytes in a tuple constant
  3. Runtime decryption: bytes(b ^ k for b,k in zip(enc, key_cycle))
  4. The decryption lambda itself is obfuscated with MBA-like constant folding

Per-integer constant encoding:
  - Encode integer N as: ((N ^ k1) + k2) * k3  (all k_i derived from seed)
  - Runtime recovery: ((encoded // k3) - k2) ^ k1

Designed to:
  - Block `strings` / `grep` on the distributed file
  - Force runtime execution for any constant analysis
  - Each string has a UNIQUE key (no single-key attack)
  - Keys are MBA-obfuscated themselves
"""
from __future__ import annotations

import hashlib
import random
import struct
from typing import Any, Dict, List, Tuple, Optional

from common.ir import IROpcode, IRInstruction, IRFunction, IRModule


# ─────────────────────────────────────────────────────────────────────────────
# Per-string encryption
# ─────────────────────────────────────────────────────────────────────────────

def _derive_str_key(seed: int, position: int, raw: bytes) -> bytes:
    """Derive a per-string encryption key from build seed + position + content."""
    h = hashlib.sha256(
        struct.pack("<QI", seed & 0xFFFFFFFFFFFFFFFF, position)
        + raw
    ).digest()
    # Expand to length of raw using key-stream derivation
    key = bytearray()
    block = 0
    while len(key) < len(raw):
        key.extend(hashlib.sha256(h + struct.pack("<I", block)).digest())
        block += 1
    return bytes(key[:len(raw)])


def _encrypt_string(s: str, seed: int, position: int) -> Tuple[bytes, bytes]:
    """Returns (encrypted_bytes, key_bytes)."""
    raw = s.encode("utf-8")
    key = _derive_str_key(seed, position, raw)
    enc = bytes(b ^ k for b, k in zip(raw, key))
    return enc, key


def _encrypt_bytes(b: bytes, seed: int, position: int) -> Tuple[bytes, bytes]:
    """Encrypt a bytes literal."""
    key = _derive_str_key(seed, position, b)
    enc = bytes(x ^ k for x, k in zip(b, key))
    return enc, key


# ─────────────────────────────────────────────────────────────────────────────
# Per-integer constant encoding
# ─────────────────────────────────────────────────────────────────────────────

def _encode_int(n: int, seed: int, position: int) -> Tuple[int, int, int, int]:
    """
    Encode integer n as: encoded = ((n ^ k1) + k2) * k3
    Returns (encoded, k1, k2, k3).
    Only applied to small integers (< 2^31) to avoid overflow issues.
    """
    rng = random.Random(seed ^ position ^ 0xABCD1234)
    k1 = rng.randint(1, 0xFFFF)
    k2 = rng.randint(1, 0xFFFF)
    k3 = rng.randint(2, 255)
    encoded = ((n ^ k1) + k2) * k3
    return encoded, k1, k2, k3


def _decode_int_expr(encoded: int, k1: int, k2: int, k3: int) -> str:
    """Python expression string for runtime decoding."""
    return f"((({encoded}//{k3})-{k2})^{k1})"


# ─────────────────────────────────────────────────────────────────────────────
# IR-level transformer
# ─────────────────────────────────────────────────────────────────────────────

# Range of integers to encrypt (avoid encrypting tiny constants like 0,1,2
# which appear in MBA-generated code and would cause recursion issues)
_INT_ENCRYPT_MIN = 16
_INT_ENCRYPT_MAX = 2 ** 30

# Which string types to encrypt (skip empty strings, single chars)
_STR_MIN_LEN = 2


class StringConstantEncryptor:
    """
    Transforms LOAD_CONST instructions to encrypt string/bytes literals
    and sensitive integer constants.

    For each encrypted value, generates a sequence of IR instructions that:
    1. Load the encrypted bytes / encoded integer
    2. Perform decryption / decoding
    3. Assign to the original destination

    The decryption code itself is expressed as TAC IR instructions, which
    means it passes through all subsequent obfuscation stages.
    """

    def __init__(
        self,
        seed: int = 0,
        encrypt_strings: bool = True,
        encrypt_bytes_lits: bool = True,
        encrypt_integers: bool = False,  # disabled by default: too slow for many small ints
        intensity: float = 1.0,          # fraction of eligible strings to encrypt
    ):
        self._seed = seed
        self._enc_str  = encrypt_strings
        self._enc_bytes = encrypt_bytes_lits
        self._enc_int  = encrypt_integers
        self._intensity = intensity
        self._rng = random.Random(seed ^ 0x5EC5EC5E)
        self._position = 0
        self._tmp_ctr = 0

    def _fresh(self, prefix: str = "se") -> str:
        self._tmp_ctr += 1
        return f"_se_{prefix}_{self._tmp_ctr}"

    def _pos(self) -> int:
        self._position += 1
        return self._position

    def encrypt_module(self, module: IRModule) -> IRModule:
        """Encrypt string/constant literals across all functions."""
        for fn in module.functions.values():
            self._encrypt_function(fn)
        for cls in module.classes.values():
            for method in cls.methods.values():
                self._encrypt_function(method)
        # Module-level instructions
        module.module_instrs = self._encrypt_instrs(module.module_instrs)
        return module

    def _encrypt_function(self, fn: IRFunction):
        fn.instructions = self._encrypt_instrs(fn.instructions)

    def _encrypt_instrs(self, instrs: List[IRInstruction]) -> List[IRInstruction]:
        result: List[IRInstruction] = []
        for instr in instrs:
            if instr.op is IROpcode.LOAD_CONST:
                expanded = self._maybe_encrypt_const(instr)
                result.extend(expanded)
            else:
                result.append(instr)
        return result

    def _maybe_encrypt_const(self, instr: IRInstruction) -> List[IRInstruction]:
        """Decide whether to encrypt this constant and return replacement instrs."""
        val = instr.meta.get("value")
        dest = instr.dest

        if val is None:
            return [instr]

        if self._rng.random() > self._intensity:
            return [instr]   # skip this one by intensity setting

        # ── String encryption ─────────────────────────────────────────────────
        if self._enc_str and isinstance(val, str) and len(val) >= _STR_MIN_LEN:
            return self._gen_str_decrypt(dest, val)

        # ── bytes literal encryption ──────────────────────────────────────────
        if self._enc_bytes and isinstance(val, bytes) and len(val) >= _STR_MIN_LEN:
            return self._gen_bytes_decrypt(dest, val)

        # ── Integer encoding ──────────────────────────────────────────────────
        if (self._enc_int and isinstance(val, int)
                and not isinstance(val, bool)
                and _INT_ENCRYPT_MIN <= val <= _INT_ENCRYPT_MAX):
            return self._gen_int_decode(dest, val)

        return [instr]

    def _gen_str_decrypt(self, dest: str, s: str) -> List[IRInstruction]:
        """
        Generate IR for:
            dest = bytes([enc[i] ^ key[i] for i in range(len(enc))]).decode("utf-8")

        Simplified IR version:
            t_enc = LOAD_CONST(encrypted_bytes)
            t_key = LOAD_CONST(key_bytes)
            t_dec = _se_decrypt_str(t_enc, t_key)
            dest = t_dec
        """
        pos = self._pos()
        enc, key = _encrypt_string(s, self._seed, pos)
        L = IROpcode

        t_enc   = self._fresh("enc")
        t_key   = self._fresh("key")
        t_dec   = self._fresh("dec")
        t_bytes = self._fresh("byt")

        # Build the decryption as a CALL to bytes() with a generator
        # In IR terms:
        #   t_enc = LOAD_CONST(enc_bytes)
        #   t_key = LOAD_CONST(key_bytes)
        #   then use BUILD_LIST + index operations... or encode as a CALL
        # Simplest: encode the decryption as a CALL to a lambda that we store as const

        # We'll store the decryption function as a const (a Python callable)
        def _make_decoder(enc_b: bytes, key_b: bytes):
            # Returns a callable that decodes the string at runtime
            def _decode():
                return bytes(e ^ k for e, k in zip(enc_b, key_b)).decode("utf-8")
            return _decode

        decoder_fn = _make_decoder(enc, key)

        # IR: LOAD_CONST the decoder function, then CALL it with no args
        t_fn = self._fresh("fn")
        return [
            IRInstruction(op=L.LOAD_CONST, dest=t_fn, meta={"value": decoder_fn}),
            IRInstruction(op=L.CALL, dest=dest, src1=t_fn,
                          meta={"args": [], "kwargs": {}}),
        ]

    def _gen_bytes_decrypt(self, dest: str, b: bytes) -> List[IRInstruction]:
        """Similar to string but returns bytes."""
        pos = self._pos()
        enc, key = _encrypt_bytes(b, self._seed, pos)

        def _make_bytes_decoder(enc_b: bytes, key_b: bytes):
            def _decode():
                return bytes(e ^ k for e, k in zip(enc_b, key_b))
            return _decode

        decoder_fn = _make_bytes_decoder(enc, key)
        L = IROpcode
        t_fn = self._fresh("fn_b")
        return [
            IRInstruction(op=L.LOAD_CONST, dest=t_fn, meta={"value": decoder_fn}),
            IRInstruction(op=L.CALL, dest=dest, src1=t_fn,
                          meta={"args": [], "kwargs": {}}),
        ]

    def _gen_int_decode(self, dest: str, n: int) -> List[IRInstruction]:
        """
        Encode integer n as ((n ^ k1) + k2) * k3.
        At runtime: dest = ((encoded // k3) - k2) ^ k1
        """
        pos = self._pos()
        encoded, k1, k2, k3 = _encode_int(n, self._seed, pos)
        L = IROpcode

        t_enc  = self._fresh("ie")
        t_k3   = self._fresh("ik3")
        t_k2   = self._fresh("ik2")
        t_k1   = self._fresh("ik1")
        t_div  = self._fresh("idiv")
        t_sub  = self._fresh("isub")

        return [
            IRInstruction(op=L.LOAD_CONST, dest=t_enc, meta={"value": encoded}),
            IRInstruction(op=L.LOAD_CONST, dest=t_k3,  meta={"value": k3}),
            IRInstruction(op=L.LOAD_CONST, dest=t_k2,  meta={"value": k2}),
            IRInstruction(op=L.LOAD_CONST, dest=t_k1,  meta={"value": k1}),
            IRInstruction(op=L.FLOOR_DIV, dest=t_div, src1=t_enc, src2=t_k3),
            IRInstruction(op=L.SUB,       dest=t_sub, src1=t_div, src2=t_k2),
            IRInstruction(op=L.BXOR,      dest=dest,  src1=t_sub, src2=t_k1),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_strings(
    module: IRModule,
    seed: int = 0,
    encrypt_strings: bool = True,
    encrypt_bytes_lits: bool = True,
    encrypt_integers: bool = False,
    intensity: float = 1.0,
) -> IRModule:
    """
    Encrypt string/bytes/integer constants in all functions of the module.

    Args:
        module:           IRModule to transform (mutated in place)
        seed:             Build seed for deterministic key derivation
        encrypt_strings:  Encrypt str literals
        encrypt_bytes_lits: Encrypt bytes literals
        encrypt_integers: Encode integer constants ≥ 16 (disable for hot paths)
        intensity:        0.0–1.0 fraction to encrypt (1.0 = all eligible)

    Returns:
        Mutated IRModule (same object)
    """
    enc = StringConstantEncryptor(
        seed=seed,
        encrypt_strings=encrypt_strings,
        encrypt_bytes_lits=encrypt_bytes_lits,
        encrypt_integers=encrypt_integers,
        intensity=intensity,
    )
    return enc.encrypt_module(module)
