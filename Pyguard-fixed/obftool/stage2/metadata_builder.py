"""
Module 2.4 – SR-VM Metadata Builder
Assembles the full SR-VM metadata bundle that the loader and runtime
need to reconstruct and execute the VM.

Metadata stored per function:
  - n_registers   : int  (how many hardware registers the function uses)
  - stack_size    : int  (max stack depth estimate)
  - entry_offset  : int  (byte offset of first instruction, after labels resolved)
  - n_consts      : int
  - n_names       : int
  - is_generator  : bool
  - is_async      : bool
  - const_table   : list[Any]   (serialised as msgpack-style binary)
  - name_table    : list[str]
  - label_map     : dict[str, int]  (label → byte offset, for debugging)

Module-level metadata:
  - dispatch_seed : bytes (8 bytes, encrypted separately)
  - build_salt    : bytes
  - functions     : dict[str, FunctionMeta]
  - entry_func    : str   (the "<module>" entry point)
"""

from __future__ import annotations
import json
import struct
import pickle
import base64
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional

from stage2.srvm_compiler   import Bytecode
from stage2.bytecode_encryptor import EncryptedBytecode


# ─────────────────────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FunctionMeta:
    name:          str
    n_registers:   int        = 16
    stack_size:    int        = 64
    entry_offset:  int        = 0
    n_consts:      int        = 0
    n_names:       int        = 0
    is_generator:  bool       = False
    is_async:      bool       = False
    const_table:   List[Any]  = field(default_factory=list)
    name_table:    List[str]  = field(default_factory=list)
    label_map:     Dict[str, int] = field(default_factory=dict)
    # encrypted bytecode sizes (for validation)
    encrypted_size: int       = 0
    nonce:         bytes      = field(default_factory=bytes)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['nonce'] = base64.b64encode(d['nonce']).decode()
        # const_table may have non-JSON-serialisable values
        d['const_table'] = _safe_json_consts(self.const_table)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "FunctionMeta":
        d = dict(d)
        d['nonce'] = base64.b64decode(d.get('nonce', ''))
        return cls(**d)


@dataclass
class SRVMModuleMeta:
    module_name:    str
    entry_func:     str           = "<module>"
    dispatch_seed:  bytes         = field(default_factory=bytes)  # 8 bytes
    build_salt:     bytes         = field(default_factory=bytes)  # 16 bytes
    functions:      Dict[str, FunctionMeta] = field(default_factory=dict)
    # version / fingerprint
    vm_version:     int           = 1
    build_id:       str           = ""

    def to_dict(self) -> dict:
        return {
            "module_name":   self.module_name,
            "entry_func":    self.entry_func,
            "dispatch_seed": base64.b64encode(self.dispatch_seed).decode(),
            "build_salt":    base64.b64encode(self.build_salt).decode(),
            "vm_version":    self.vm_version,
            "build_id":      self.build_id,
            "functions":     {k: v.to_dict() for k, v in self.functions.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SRVMModuleMeta":
        fns = {k: FunctionMeta.from_dict(v) for k, v in d.get("functions", {}).items()}
        return cls(
            module_name   = d["module_name"],
            entry_func    = d.get("entry_func", "<module>"),
            dispatch_seed = base64.b64decode(d.get("dispatch_seed", "")),
            build_salt    = base64.b64decode(d.get("build_salt", "")),
            vm_version    = d.get("vm_version", 1),
            build_id      = d.get("build_id", ""),
            functions     = fns,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Builder
# ─────────────────────────────────────────────────────────────────────────────

class SRVMMetaBuilder:
    """
    Takes compiled Bytecode objects + EncryptedBytecode objects and
    assembles the SRVMModuleMeta + serialised binary header.
    """

    def build(
        self,
        module_name:    str,
        bytecodes:      Dict[str, Bytecode],
        encrypted:      Dict[str, EncryptedBytecode],
        dispatch_seed:  bytes,
        build_salt:     bytes,
        build_id:       str  = "",
        ir_module=None,      # optional IRModule for generator/async flags
    ) -> SRVMModuleMeta:

        meta = SRVMModuleMeta(
            module_name   = module_name,
            entry_func    = "<module>",
            dispatch_seed = dispatch_seed,
            build_salt    = build_salt,
            build_id      = build_id,
        )

        for fn_name, bc in bytecodes.items():
            enc = encrypted.get(fn_name)
            fm  = self._build_fn_meta(fn_name, bc, enc, ir_module)
            meta.functions[fn_name] = fm

        return meta

    def _build_fn_meta(
        self,
        fn_name:  str,
        bc:       Bytecode,
        enc:      Optional[EncryptedBytecode],
        ir_module,
    ) -> FunctionMeta:
        # Estimate register count from bytecode
        n_regs = self._estimate_registers(bc)

        # Estimate stack depth (each PUSH_* adds 1, ops pop 1-2 and push 1)
        stack_size = max(64, self._estimate_stack(bc))

        # entry_offset is always 0 (first instruction after labels resolved)
        entry_offset = 0
        # find first non-label position
        if bc.raw:
            entry_offset = 0

        # get generator/async flags from IR if available
        is_gen = is_async = False
        if ir_module:
            fn = ir_module.functions.get(fn_name)
            if fn:
                is_gen   = fn.is_generator
                is_async = fn.is_async

        return FunctionMeta(
            name           = fn_name,
            n_registers    = n_regs,
            stack_size     = stack_size,
            entry_offset   = entry_offset,
            n_consts       = len(bc.const_table),
            n_names        = len(bc.name_table),
            is_generator   = is_gen,
            is_async       = is_async,
            const_table    = list(bc.const_table),
            name_table     = list(bc.name_table),
            label_map      = dict(bc.label_offsets),
            encrypted_size = len(enc.ciphertext) if enc else 0,
            nonce          = enc.nonce if enc else b"",
        )

    def _estimate_registers(self, bc: Bytecode) -> int:
        """Scan raw bytecode for max register index referenced."""
        from stage2.opcode_poly_gen import LogicalOp
        # We can't fully decode without the dispatch table here,
        # so use a conservative default based on bytecode length.
        # A more precise version is done inside the VM at runtime.
        n_instrs = len(bc.raw) // 3
        return min(16, max(8, n_instrs // 10))

    def _estimate_stack(self, bc: Bytecode) -> int:
        """Rough upper bound on stack depth."""
        n_instrs = len(bc.raw) // 3
        return max(64, n_instrs // 2)


# ─────────────────────────────────────────────────────────────────────────────
# Binary Serialisation of Metadata
# ─────────────────────────────────────────────────────────────────────────────

HEADER_MAGIC   = b"SRVMHDR\x01"
HEADER_VERSION = 1


class MetaSerializer:
    """
    Serialises SRVMModuleMeta to/from a compact binary header.

    Header layout:
      [8B: magic]
      [2B: version]
      [2B: json_meta_len]
      [json_meta_len bytes: UTF-8 JSON of SRVMModuleMeta.to_dict()]
      [4B: crc32 of above]
    """

    def serialise(self, meta: SRVMModuleMeta) -> bytes:
        import zlib
        json_bytes = json.dumps(meta.to_dict(), ensure_ascii=False).encode("utf-8")
        crc = zlib.crc32(json_bytes) & 0xFFFFFFFF
        pieces = [
            HEADER_MAGIC,
            struct.pack('<H', HEADER_VERSION),
            struct.pack('<I', len(json_bytes)),
            json_bytes,
            struct.pack('<I', crc),
        ]
        return b"".join(pieces)

    def deserialise(self, data: bytes) -> SRVMModuleMeta:
        import zlib
        off = 0
        assert data[off:off+8] == HEADER_MAGIC, "Bad SRVM header magic"
        off += 8
        version = struct.unpack('<H', data[off:off+2])[0]; off += 2
        json_len = struct.unpack('<I', data[off:off+4])[0]; off += 4
        json_bytes = data[off:off+json_len]; off += json_len
        stored_crc = struct.unpack('<I', data[off:off+4])[0]
        actual_crc = zlib.crc32(json_bytes) & 0xFFFFFFFF
        assert stored_crc == actual_crc, "SRVM metadata CRC mismatch – tampering detected"
        return SRVMModuleMeta.from_dict(json.loads(json_bytes.decode("utf-8")))

    def to_json(self, meta: SRVMModuleMeta) -> str:
        return json.dumps(meta.to_dict(), indent=2, ensure_ascii=False)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _safe_json_consts(consts: list) -> list:
    """Convert const_table values to JSON-safe representations."""
    safe = []
    for v in consts:
        if isinstance(v, (int, float, bool, str, type(None))):
            safe.append(v)
        elif isinstance(v, bytes):
            safe.append({"__bytes__": base64.b64encode(v).decode()})
        elif isinstance(v, complex):
            safe.append({"__complex__": [v.real, v.imag]})
        else:
            safe.append({"__repr__": repr(v)})
    return safe


# ─── convenience ─────────────────────────────────────────────────────────────

def build_metadata(
    module_name:   str,
    bytecodes:     Dict[str, Bytecode],
    encrypted:     Dict[str, EncryptedBytecode],
    dispatch_seed: bytes,
    build_salt:    bytes,
    ir_module=None,
    build_id:      str = "",
) -> tuple[SRVMModuleMeta, bytes]:
    """
    Returns (meta, header_bytes).
    header_bytes is the binary-serialised metadata for embedding in payload.
    """
    builder    = SRVMMetaBuilder()
    serializer = MetaSerializer()
    meta       = builder.build(
        module_name   = module_name,
        bytecodes     = bytecodes,
        encrypted     = encrypted,
        dispatch_seed = dispatch_seed,
        build_salt    = build_salt,
        build_id      = build_id,
        ir_module     = ir_module,
    )
    header_bytes = serializer.serialise(meta)
    return meta, header_bytes
