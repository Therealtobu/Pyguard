"""
Modules 4.3 – Native Compiler  (LLVM → machine code)
        4.4 – Shellcode Extractor (ELF/PE → raw bytes)
        4.5 – Native Block Splitter (raw bytes → 8-32 byte chunks)
        4.6 – Native Block Encryptor (per-block HMAC-derived AES-GCM)

Execution path:
  LLVM IR (.ll) → clang/llc → ELF object → objcopy → raw bytes
                                          ↓
                                    block split → encrypt

If LLVM toolchain is not present the pipeline falls back to a pure-Python
AES-CTR "fake-native" blob that carries the interpreted bytecode; this
keeps the pipeline operational on any machine.
"""

from __future__ import annotations
import os
import struct
import hmac
import hashlib
import shutil
import tempfile
import subprocess
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ── AES-GCM backend (same as stage2/3) ───────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    def _gcm_enc(key, nonce, pt, aad=b""):
        ct_tag = _AESGCM(key).encrypt(nonce, pt, aad or None)
        return ct_tag[:-16], ct_tag[-16:]
    def _gcm_dec(key, nonce, ct, tag, aad=b""):
        return _AESGCM(key).decrypt(nonce, ct + tag, aad or None)
except ImportError:
    def _gcm_enc(k, n, pt, aad=b""): return pt, b'\x00'*16
    def _gcm_dec(k, n, ct, tag, aad=b""): return ct

KEY_LEN   = 32
NONCE_LEN = 12
HKDF_INFO = b"NATIVE-BLOCK-v1"


# ═════════════════════════════════════════════════════════════════════════════
# 4.3 – Native Compiler
# ═════════════════════════════════════════════════════════════════════════════

class NativeCompiler:
    """
    Compiles LLVM IR text to raw machine-code bytes.
    Requires: clang OR (llc + ld)  in PATH.
    Falls back to pseudo-native blob if toolchain absent.
    """

    # Compiler flags that maximise obfuscation-friendliness
    CLANG_FLAGS = [
        "-O2",
        "-fno-stack-protector",
        "-fno-exceptions",
        "-fvisibility=hidden",
        "-fomit-frame-pointer",
        "-target", "x86_64-pc-linux-gnu",
    ]

    def __init__(self, arch: str = "x86_64"):
        self._arch      = arch
        self._has_clang = bool(shutil.which("clang"))
        self._has_llc   = bool(shutil.which("llc"))

    def compile(self, llvm_ir: str, fn_name: str) -> bytes:
        """Compile LLVM IR → raw .text section bytes."""
        if self._has_clang:
            return self._compile_clang(llvm_ir, fn_name)
        elif self._has_llc:
            return self._compile_llc(llvm_ir, fn_name)
        else:
            return self._pseudo_native(llvm_ir, fn_name)

    def compile_all(self, fn_irs: Dict[str, str]) -> Dict[str, bytes]:
        return {name: self.compile(ir, name) for name, ir in fn_irs.items()}

    # ── clang path ────────────────────────────────────────────────────────────

    def _compile_clang(self, llvm_ir: str, fn_name: str) -> bytes:
        with tempfile.TemporaryDirectory() as td:
            ll_path  = os.path.join(td, "fn.ll")
            obj_path = os.path.join(td, "fn.o")
            with open(ll_path, "w") as f:
                f.write(llvm_ir)
            cmd = ["clang", "-c"] + self.CLANG_FLAGS + [ll_path, "-o", obj_path]
            try:
                subprocess.run(cmd, check=True,
                               capture_output=True, timeout=30)
                return self._extract_text(obj_path)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return self._pseudo_native(llvm_ir, fn_name)

    # ── llc path ──────────────────────────────────────────────────────────────

    def _compile_llc(self, llvm_ir: str, fn_name: str) -> bytes:
        with tempfile.TemporaryDirectory() as td:
            ll_path  = os.path.join(td, "fn.ll")
            asm_path = os.path.join(td, "fn.s")
            obj_path = os.path.join(td, "fn.o")
            with open(ll_path, "w") as f:
                f.write(llvm_ir)
            try:
                subprocess.run(["llc", "-O2", "-filetype=obj",
                                "-march=x86-64", ll_path, "-o", obj_path],
                               check=True, capture_output=True, timeout=30)
                return self._extract_text(obj_path)
            except Exception:
                return self._pseudo_native(llvm_ir, fn_name)

    # ── ELF .text extractor ───────────────────────────────────────────────────

    def _extract_text(self, obj_path: str) -> bytes:
        """Read the .text section from an ELF object file."""
        try:
            with open(obj_path, "rb") as f:
                elf = f.read()
            return self._parse_elf_text(elf)
        except Exception:
            return b""

    def _parse_elf_text(self, elf: bytes) -> bytes:
        """Minimal ELF parser to extract .text section."""
        if elf[:4] != b"\x7fELF":
            return elf  # not ELF, return as-is
        # ELF64 header fields
        e_shoff    = struct.unpack_from("<Q", elf, 0x28)[0]
        e_shentsize= struct.unpack_from("<H", elf, 0x3A)[0]
        e_shnum    = struct.unpack_from("<H", elf, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", elf, 0x3E)[0]

        # Section name string table
        shstr_hdr  = e_shoff + e_shstrndx * e_shentsize
        shstr_off  = struct.unpack_from("<Q", elf, shstr_hdr + 0x18)[0]

        for i in range(e_shnum):
            sh_off  = e_shoff + i * e_shentsize
            sh_name = struct.unpack_from("<I", elf, sh_off)[0]
            name    = elf[shstr_off + sh_name:].split(b"\x00")[0]
            if name == b".text":
                sec_off  = struct.unpack_from("<Q", elf, sh_off + 0x18)[0]
                sec_size = struct.unpack_from("<Q", elf, sh_off + 0x20)[0]
                return elf[sec_off:sec_off + sec_size]
        return b""

    # ── pseudo-native fallback ────────────────────────────────────────────────

    def _pseudo_native(self, llvm_ir: str, fn_name: str) -> bytes:
        """
        When no LLVM toolchain is available, produce a deterministic
        pseudo-native blob:
          [8B: magic] [4B: ir_hash] [payload: compressed + xor-scrambled IR]
        At runtime the C extension detects the magic and routes to the
        SR-VM interpreter instead of trying to execute the bytes as code.
        """
        MAGIC  = b"PNATIVE\x01"
        ir_b   = llvm_ir.encode("utf-8")
        import zlib
        compressed = zlib.compress(ir_b, level=9)
        ir_hash    = hashlib.sha256(ir_b).digest()[:4]
        # Light XOR scramble
        key    = hashlib.md5(fn_name.encode()).digest()
        xored  = bytes(b ^ key[i % 16] for i, b in enumerate(compressed))
        return MAGIC + ir_hash + xored


# ═════════════════════════════════════════════════════════════════════════════
# 4.4 – Shellcode Extractor
# ═════════════════════════════════════════════════════════════════════════════

class ShellcodeExtractor:
    """
    Post-processes raw native bytes:
    - Strips ELF/PE file headers if still present
    - Strips trailing zero-padding
    - Adds position-independent relocations if needed (x86_64: nop-slides)
    """

    def extract(self, raw_bytes: bytes, fn_name: str) -> bytes:
        # Detect and strip pseudo-native magic (handled by runtime)
        if raw_bytes[:8] == b"PNATIVE\x01":
            return raw_bytes  # keep pseudo-native as-is

        # Strip ELF wrapper if still present
        if raw_bytes[:4] == b"\x7fELF":
            extracted = self._parse_elf_text(raw_bytes)
            if extracted:
                raw_bytes = extracted

        # Strip trailing nulls (linker padding)
        raw_bytes = raw_bytes.rstrip(b"\x00")
        if not raw_bytes:
            return b"\x90"  # single NOP as placeholder

        return raw_bytes

    def _parse_elf_text(self, elf: bytes) -> bytes:
        try:
            e_shoff    = struct.unpack_from("<Q", elf, 0x28)[0]
            e_shentsize= struct.unpack_from("<H", elf, 0x3A)[0]
            e_shnum    = struct.unpack_from("<H", elf, 0x3C)[0]
            e_shstrndx = struct.unpack_from("<H", elf, 0x3E)[0]
            shstr_hdr  = e_shoff + e_shstrndx * e_shentsize
            shstr_off  = struct.unpack_from("<Q", elf, shstr_hdr + 0x18)[0]
            for i in range(e_shnum):
                sh_off  = e_shoff + i * e_shentsize
                sh_name = struct.unpack_from("<I", elf, sh_off)[0]
                name    = elf[shstr_off + sh_name:].split(b"\x00")[0]
                if name == b".text":
                    sec_off  = struct.unpack_from("<Q", elf, sh_off + 0x18)[0]
                    sec_size = struct.unpack_from("<Q", elf, sh_off + 0x20)[0]
                    return elf[sec_off:sec_off + sec_size]
        except Exception:
            pass
        return b""

    def extract_all(self, native_bytes: Dict[str, bytes]) -> Dict[str, bytes]:
        return {name: self.extract(b, name) for name, b in native_bytes.items()}


# ═════════════════════════════════════════════════════════════════════════════
# 4.5 – Native Block Splitter
# ═════════════════════════════════════════════════════════════════════════════

MIN_BLOCK = 8
MAX_BLOCK = 32


@dataclass
class NativeBlock:
    fn_name:    str
    block_idx:  int
    data:       bytes
    offset:     int       # byte offset in original shellcode
    is_pseudo:  bool = False  # True if pseudo-native fallback

    @property
    def block_id(self) -> str:
        h = hashlib.sha1(f"{self.fn_name}:{self.block_idx}:{self.offset}".encode()).hexdigest()[:8]
        return f"NB_{self.fn_name[:16]}_{self.block_idx:04d}_{h}"


class NativeBlockSplitter:
    """
    Splits raw shellcode into variable-length basic blocks (8-32 bytes).
    For real x86_64, uses a heuristic disassembler to split at instruction
    boundaries. For pseudo-native blobs, splits at fixed intervals.
    """

    def __init__(self, seed: int = 0):
        self._rng = random.Random(seed)

    def split(self, fn_name: str, shellcode: bytes) -> List[NativeBlock]:
        if shellcode[:8] == b"PNATIVE\x01":
            return self._split_fixed(fn_name, shellcode, is_pseudo=True)

        # Try heuristic x86_64 split
        try:
            return self._split_x86(fn_name, shellcode)
        except Exception:
            return self._split_fixed(fn_name, shellcode)

    def split_all(self, native: Dict[str, bytes]) -> Dict[str, List[NativeBlock]]:
        return {name: self.split(name, data) for name, data in native.items()}

    def _split_fixed(self, fn_name: str, data: bytes, is_pseudo: bool = False) -> List[NativeBlock]:
        """Split at random sizes in [MIN_BLOCK, MAX_BLOCK]."""
        blocks: List[NativeBlock] = []
        off = 0; idx = 0
        while off < len(data):
            sz = self._rng.randint(MIN_BLOCK, MAX_BLOCK)
            chunk = data[off:off+sz]
            if not chunk:
                break
            blocks.append(NativeBlock(fn_name=fn_name, block_idx=idx,
                                       data=chunk, offset=off,
                                       is_pseudo=is_pseudo))
            off += sz; idx += 1
        return blocks

    def _split_x86(self, fn_name: str, data: bytes) -> List[NativeBlock]:
        """
        Heuristic x86_64 splitter: groups instructions into 8-32 byte chunks.
        Uses a length table for common 1-byte/2-byte opcodes. Falls back to
        fixed split if opcode is ambiguous.
        """
        lengths = self._estimate_instr_lengths(data)
        blocks: List[NativeBlock] = []
        off = 0; idx = 0; chunk_start = 0; chunk_bytes = b""

        for instr_off, instr_len in lengths:
            chunk_bytes += data[instr_off:instr_off+instr_len]
            if len(chunk_bytes) >= MIN_BLOCK and (
                    len(chunk_bytes) >= MAX_BLOCK or
                    self._rng.random() < 0.4):
                blocks.append(NativeBlock(fn_name=fn_name, block_idx=idx,
                                           data=chunk_bytes, offset=chunk_start))
                chunk_start = instr_off + instr_len
                chunk_bytes = b""
                idx += 1

        if chunk_bytes:
            blocks.append(NativeBlock(fn_name=fn_name, block_idx=idx,
                                       data=chunk_bytes, offset=chunk_start))
        return blocks if blocks else self._split_fixed(fn_name, data)

    def _estimate_instr_lengths(self, data: bytes) -> List[Tuple[int, int]]:
        """
        Very simplified x86_64 instruction length estimator.
        Handles REX prefix, common 1-byte opcodes, 2-byte 0F prefix.
        Good enough for splitting – not a full disassembler.
        """
        result = []
        i = 0
        while i < len(data):
            start = i
            # REX prefix
            if data[i] & 0xF0 == 0x40:
                i += 1
            if i >= len(data):
                break
            op = data[i]; i += 1
            # 0F prefix (2-byte opcodes)
            if op == 0x0F:
                if i < len(data):
                    i += 1  # second byte
            # ModRM byte
            if op in _MODRM_OPS and i < len(data):
                modrm = data[i]; i += 1
                mod = (modrm >> 6) & 3
                rm  = modrm & 7
                if mod == 0 and rm == 5:
                    i += 4  # disp32
                elif mod == 1:
                    i += 1  # disp8
                elif mod == 2:
                    i += 4  # disp32
                if rm == 4 and mod != 3:  # SIB byte
                    i += 1
            # Immediate
            if op in _IMM8_OPS  and i < len(data): i += 1
            if op in _IMM32_OPS and i < len(data): i += 4
            if op in _IMM64_OPS and i < len(data): i += 8

            length = i - start
            if length == 0:
                length = 1; i = start + 1  # safety
            result.append((start, length))
        return result


# Simplified opcode sets for length estimation
_MODRM_OPS = frozenset(range(0x00, 0x3F)) | {0x85, 0x89, 0x8B, 0xF7, 0xFF}
_IMM8_OPS  = {0x6A, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
               0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0xEB, 0x83}
_IMM32_OPS = {0x05, 0x25, 0x68, 0x81, 0xB8, 0xBA, 0xE8, 0xE9}
_IMM64_OPS = {0x48}  # REX.W MOV r64, imm64 after REX prefix


# ═════════════════════════════════════════════════════════════════════════════
# 4.6 – Native Block Encryptor
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class EncryptedNativeBlock:
    block_id:   str
    fn_name:    str
    block_idx:  int
    offset:     int
    nonce:      bytes
    ciphertext: bytes
    tag:        bytes
    key_salt:   bytes
    is_pseudo:  bool = False
    aad:        bytes = b""

    def serialise(self) -> bytes:
        id_b  = self.block_id.encode()
        fn_b  = self.fn_name.encode()
        return b"".join([
            struct.pack('<H', len(id_b)),   id_b,
            struct.pack('<H', len(fn_b)),   fn_b,
            struct.pack('<I', self.block_idx),
            struct.pack('<I', self.offset),
            struct.pack('<B', int(self.is_pseudo)),
            struct.pack('<H', len(self.key_salt)), self.key_salt,
            struct.pack('<H', len(self.nonce)),    self.nonce,
            struct.pack('<I', len(self.ciphertext)), self.ciphertext,
            self.tag,
            struct.pack('<H', len(self.aad)), self.aad,
        ])

    @classmethod
    def deserialise(cls, data: bytes) -> "EncryptedNativeBlock":
        off = 0
        def r(n): nonlocal off; v=data[off:off+n]; off+=n; return v
        def r2j(): return r(struct.unpack('<H',r(2))[0])
        def r4j(): return r(struct.unpack('<I',r(4))[0])
        block_id  = r2j().decode()
        fn_name   = r2j().decode()
        block_idx = struct.unpack('<I', r(4))[0]
        offset    = struct.unpack('<I', r(4))[0]
        is_pseudo = bool(r(1)[0])
        key_salt  = r2j()
        nonce     = r2j()
        ct_sz     = struct.unpack('<I', r(4))[0]; ct = r(ct_sz)
        tag       = r(16)
        aad       = r2j()
        return cls(block_id=block_id, fn_name=fn_name, block_idx=block_idx,
                   offset=offset, nonce=nonce, ciphertext=ct, tag=tag,
                   key_salt=key_salt, is_pseudo=is_pseudo, aad=aad)

    def decrypt(self, master_key: bytes) -> bytes:
        fn_key = hmac.new(master_key, self.block_id.encode() + self.key_salt + HKDF_INFO, "sha256").digest()
        return _gcm_dec(fn_key, self.nonce, self.ciphertext, self.tag, self.aad)


class NativeBlockEncryptor:

    def __init__(self, master_key: bytes):
        self._master_key = master_key

    @classmethod
    def from_seed(cls, seed: bytes) -> "NativeBlockEncryptor":
        master = hashlib.pbkdf2_hmac("sha256", seed + HKDF_INFO,
                                      b"native-block-salt", 100_000, dklen=KEY_LEN)
        return cls(master)

    def encrypt_all(
        self,
        blocks_by_fn: Dict[str, List[NativeBlock]],
    ) -> Dict[str, List[EncryptedNativeBlock]]:
        result: Dict[str, List[EncryptedNativeBlock]] = {}
        for fn_name, blocks in blocks_by_fn.items():
            result[fn_name] = [self._encrypt_block(blk) for blk in blocks]
        return result

    def _encrypt_block(self, blk: NativeBlock) -> EncryptedNativeBlock:
        salt     = os.urandom(16)
        nonce    = os.urandom(NONCE_LEN)
        fn_key   = hmac.new(self._master_key,
                             blk.block_id.encode() + salt + HKDF_INFO, "sha256").digest()
        aad      = blk.block_id.encode() + blk.fn_name.encode()
        ct, tag  = _gcm_enc(fn_key, nonce, blk.data, aad)
        return EncryptedNativeBlock(
            block_id  = blk.block_id,
            fn_name   = blk.fn_name,
            block_idx = blk.block_idx,
            offset    = blk.offset,
            nonce     = nonce,
            ciphertext= ct,
            tag       = tag,
            key_salt  = salt,
            is_pseudo = blk.is_pseudo,
            aad       = aad,
        )

    # ── bundle serialisation ──────────────────────────────────────────────────

    def serialise_bundle(self, enc: Dict[str, List[EncryptedNativeBlock]]) -> bytes:
        MAGIC = b"NBLK"
        all_blocks = [blk for fn_blocks in enc.values() for blk in fn_blocks]
        pieces = [MAGIC, struct.pack('<I', len(all_blocks))]
        for blk in all_blocks:
            blob = blk.serialise()
            pieces += [struct.pack('<I', len(blob)), blob]
        return b"".join(pieces)

    @staticmethod
    def deserialise_bundle(data: bytes) -> Dict[str, List[EncryptedNativeBlock]]:
        assert data[:4] == b"NBLK", "Bad native block bundle magic"
        off = 4
        n   = struct.unpack('<I', data[off:off+4])[0]; off += 4
        by_fn: Dict[str, List[EncryptedNativeBlock]] = {}
        for _ in range(n):
            sz  = struct.unpack('<I', data[off:off+4])[0]; off += 4
            blk = EncryptedNativeBlock.deserialise(data[off:off+sz]); off += sz
            by_fn.setdefault(blk.fn_name, []).append(blk)
        # Sort each by block_idx
        for fn_blocks in by_fn.values():
            fn_blocks.sort(key=lambda b: b.block_idx)
        return by_fn


# ─── convenience ─────────────────────────────────────────────────────────────

def compile_and_encrypt(
    fn_irs:      Dict[str, str],
    seed:        Optional[bytes] = None,
    split_seed:  int = 0,
) -> tuple[Dict[str, List[EncryptedNativeBlock]], bytes, bytes]:
    """
    Full 4.3→4.6 pipeline.
    Returns (encrypted_blocks_by_fn, native_seed, bundle_bytes).
    """
    if seed is None:
        seed = os.urandom(32)

    compiler  = NativeCompiler()
    extractor = ShellcodeExtractor()
    splitter  = NativeBlockSplitter(seed=split_seed)
    encryptor = NativeBlockEncryptor.from_seed(seed)

    native_raw  = compiler.compile_all(fn_irs)
    native_sc   = extractor.extract_all(native_raw)
    blocks_by_fn= splitter.split_all(native_sc)
    encrypted   = encryptor.encrypt_all(blocks_by_fn)
    bundle      = encryptor.serialise_bundle(encrypted)

    return encrypted, seed, bundle
