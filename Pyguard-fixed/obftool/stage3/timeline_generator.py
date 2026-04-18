"""
Module 3.2 – Timeline Generator
Assigns multiple timestamped versions to each DAG node.

Each node gets N_VERSIONS timeline slots:
  t0 = canonical value (used at runtime)
  t1 = alternate encoding  (e.g., negated / XOR'd)
  t2 = another transform
  ...
  tK = fake (never used at runtime – decoy for analysts)

Timeline structure per node:
  timelines = {
    "t0": { "value": <canonical>,    "active": True,  "dt": 0.0  },
    "t1": { "value": <transform_1>,  "active": False, "dt": 0.05 },
    "t2": { "value": <transform_2>,  "active": False, "dt": 0.10 },
    ...
    "t_fake_N": { "value": <random>, "active": False, "dt": 99.9 },
  }

At runtime the GT-VM Oracle stub (module 3.5) always returns t0 (the
canonical version) after verifying node_id authenticity. The fake
timelines exist only in the encrypted payload to confuse static analysis.
"""

from __future__ import annotations
import os
import math
import random
import struct
import hashlib
from typing import Dict, List, Any, Optional

from stage3.gtvm_graph_builder import DAGNode, ExecutionDAG, NodeKind


# ─── Value transform library ──────────────────────────────────────────────────

def _transform_int(v: int, rng: random.Random) -> List[Any]:
    """Multiple alternative encodings for an integer."""
    variants = [
        v ^ rng.randint(0, 0xFFFF),     # XOR obfuscation
        -v if v != 0 else 1,             # negated
        v + rng.randint(1, 999),         # shifted (unused)
        ~v,                              # bitwise NOT
    ]
    return variants


def _transform_str(v: str, rng: random.Random) -> List[Any]:
    """Alternative encodings for a string."""
    xor_key = rng.randint(1, 255)
    encoded = bytes(c ^ xor_key for c in v.encode()).hex()
    return [
        encoded,                  # XOR bytes as hex
        v[::-1],                  # reversed
        "".join(chr(ord(c) + 1) for c in v),  # char shift
    ]


def _transform_bool(v: bool, rng: random.Random) -> List[Any]:
    return [not v, int(v), 1 - int(v)]


def _transform_float(v: float, rng: random.Random) -> List[Any]:
    off = rng.uniform(0.1, 10.0)
    return [v + off, v - off, -v]


def _transform_none(_: None, rng: random.Random) -> List[Any]:
    return [False, 0, ""]


def _make_variants(value: Any, rng: random.Random) -> List[Any]:
    if isinstance(value, bool):
        return _transform_bool(value, rng)
    elif isinstance(value, int):
        return _transform_int(value, rng)
    elif isinstance(value, float):
        return _transform_float(value, rng)
    elif isinstance(value, str):
        return _transform_str(value, rng)
    elif value is None:
        return _transform_none(value, rng)
    else:
        return []   # complex types: no alternative encoding


def _random_fake_value(rng: random.Random) -> Any:
    kind = rng.randint(0, 4)
    if kind == 0: return rng.randint(-99999, 99999)
    if kind == 1: return rng.uniform(-100.0, 100.0)
    if kind == 2: return os.urandom(rng.randint(4, 16)).hex()
    if kind == 3: return None
    return rng.choice([True, False])


# ─────────────────────────────────────────────────────────────────────────────
# Timeline Generator
# ─────────────────────────────────────────────────────────────────────────────

N_REAL_VERSIONS = 3    # t0 (canonical) + t1 + t2 (transforms)
N_FAKE_VERSIONS = 3    # t_fake_0 .. t_fake_2 (decoys)
DT_STEP         = 0.05  # temporal gap between timeline slots


class TimelineGenerator:
    """
    Adds timestamped version slots to every node in a DAG.
    """

    def __init__(self, seed: int = 0, n_real: int = N_REAL_VERSIONS,
                 n_fake: int = N_FAKE_VERSIONS):
        self._rng    = random.Random(seed)
        self._n_real = n_real
        self._n_fake = n_fake

    # ── public ────────────────────────────────────────────────────────────────

    def annotate(self, dag: ExecutionDAG) -> ExecutionDAG:
        for node in dag.nodes.values():
            node.timelines = self._build_timelines(node)
        return dag

    def annotate_all(self, dags: Dict[str, ExecutionDAG]) -> Dict[str, ExecutionDAG]:
        for dag in dags.values():
            self.annotate(dag)
        return dags

    # ── per-node timeline ─────────────────────────────────────────────────────

    def _build_timelines(self, node: DAGNode) -> Dict[str, Dict]:
        timelines: Dict[str, Dict] = {}

        canonical = self._canonical_value(node)

        # t0 = canonical (always active at runtime)
        timelines["t0"] = {
            "value":  canonical,
            "active": True,
            "dt":     node.dt,
            "hash":   self._hash_value(canonical),
        }

        # t1..t(n_real-1) = transform variants (inactive decoys)
        variants = _make_variants(canonical, self._rng)
        for i in range(1, self._n_real):
            if i - 1 < len(variants):
                v = variants[i - 1]
            else:
                v = _random_fake_value(self._rng)
            timelines[f"t{i}"] = {
                "value":  v,
                "active": False,
                "dt":     node.dt + i * DT_STEP,
                "hash":   self._hash_value(v),
            }

        # fake timelines (completely random – never used)
        for j in range(self._n_fake):
            fake_v = _random_fake_value(self._rng)
            key    = f"t_fake_{j}"
            timelines[key] = {
                "value":  fake_v,
                "active": False,
                "dt":     node.dt + 99.0 + j * DT_STEP,
                "is_fake": True,
                "hash":   self._hash_value(fake_v),
            }

        return timelines

    def _canonical_value(self, node: DAGNode) -> Any:
        """Extract the semantically relevant value for a node."""
        if node.kind == NodeKind.CONST:
            return node.value
        elif node.kind == NodeKind.NAME:
            return node.name
        elif node.kind == NodeKind.ENTRY:
            return "__entry__"
        elif node.kind == NodeKind.EXIT:
            return "__exit__"
        else:
            # OP / CTRL / PHI nodes: use the op string as canonical
            return node.op

    def _hash_value(self, v: Any) -> str:
        try:
            raw = repr(v).encode()
        except Exception:
            raw = b"<unhashable>"
        return hashlib.sha256(raw).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# Timeline Serialiser (compact binary format)
# ─────────────────────────────────────────────────────────────────────────────

class TimelineSerialiser:
    """
    Serialises a single node's timeline dict to a compact binary blob
    for encryption in module 3.3.

    Format per timeline slot:
      [1B: key_len][key][1B: type][value_bytes][8B: dt as double][1B: flags]
    flags: bit0=active, bit1=is_fake
    """

    TYPE_NONE    = 0
    TYPE_INT     = 1
    TYPE_FLOAT   = 2
    TYPE_STR     = 3
    TYPE_BOOL    = 4
    TYPE_BYTES   = 5
    TYPE_UNKNOWN = 0xFF

    def serialise_node(self, node: DAGNode) -> bytes:
        pieces = []
        pieces.append(struct.pack('<H', len(node.timelines)))
        for key, slot in node.timelines.items():
            key_b = key.encode()
            val_b = self._encode_value(slot.get("value"))
            dt_b  = struct.pack('<d', float(slot.get("dt", 0.0)))
            flags = (0x01 if slot.get("active") else 0) | \
                    (0x02 if slot.get("is_fake") else 0)
            pieces += [
                struct.pack('<B', len(key_b)), key_b,
                val_b,
                dt_b,
                struct.pack('<B', flags),
            ]
        return b"".join(pieces)

    def deserialise_node(self, data: bytes) -> Dict[str, Dict]:
        off = 0
        n   = struct.unpack('<H', data[off:off+2])[0]; off += 2
        result = {}
        for _ in range(n):
            klen = data[off]; off += 1
            key  = data[off:off+klen].decode(); off += klen
            value, consumed = self._decode_value(data, off); off += consumed
            dt   = struct.unpack('<d', data[off:off+8])[0]; off += 8
            flags= data[off]; off += 1
            result[key] = {
                "value":  value,
                "dt":     dt,
                "active": bool(flags & 0x01),
                "is_fake":bool(flags & 0x02),
            }
        return result

    def _encode_value(self, v: Any) -> bytes:
        if v is None:
            return struct.pack('<B', self.TYPE_NONE)
        elif isinstance(v, bool):
            return struct.pack('<BB', self.TYPE_BOOL, int(v))
        elif isinstance(v, int):
            # clamp to signed 64-bit range before packing
            clamped = max(-9223372036854775808, min(9223372036854775807, int(v)))
            raw = struct.pack('<q', clamped)
            return struct.pack('<B', self.TYPE_INT) + raw
        elif isinstance(v, float):
            return struct.pack('<Bd', self.TYPE_FLOAT, v)
        elif isinstance(v, str):
            raw = v.encode("utf-8")[:255]
            return struct.pack('<BB', self.TYPE_STR, len(raw)) + raw
        elif isinstance(v, bytes):
            raw = v[:255]
            return struct.pack('<BB', self.TYPE_BYTES, len(raw)) + raw
        else:
            raw = repr(v).encode()[:255]
            return struct.pack('<BB', self.TYPE_UNKNOWN, len(raw)) + raw

    def _decode_value(self, data: bytes, off: int):
        tp = data[off]; off2 = off + 1
        if tp == self.TYPE_NONE:
            return None, 1
        elif tp == self.TYPE_BOOL:
            return bool(data[off2]), 2
        elif tp == self.TYPE_INT:
            v = struct.unpack('<q', data[off2:off2+8])[0]
            return v, 9
        elif tp == self.TYPE_FLOAT:
            v = struct.unpack('<d', data[off2:off2+8])[0]
            return v, 9
        elif tp in (self.TYPE_STR, self.TYPE_BYTES, self.TYPE_UNKNOWN):
            sz  = data[off2]; raw = data[off2+1:off2+1+sz]
            val = raw.decode("utf-8", errors="replace") if tp == self.TYPE_STR else raw
            return val, 2 + sz
        return None, 1


# ─── convenience ─────────────────────────────────────────────────────────────

def generate_timelines(
    dags: Dict[str, ExecutionDAG],
    seed: int = 0,
) -> Dict[str, ExecutionDAG]:
    gen = TimelineGenerator(seed=seed)
    return gen.annotate_all(dags)
