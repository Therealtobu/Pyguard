"""
Module 6.1 – Fragmenter
Slices all stage outputs into uniform 4-32 byte fragments.

Fragment types:
  SRVM  – SR-VM bytecode chunks
  GTVM  – GT-VM node/timeline chunks
  NATV  – Native block chunks
  WDOG  – Watchdog .so chunks
  JUNK  – Random filler (injected by 6.2)

Each fragment carries a FragmentHeader:
  frag_id   : uint32   (monotonically increasing)
  frag_type : uint8    (FragType enum)
  frag_seq  : uint16   (sequence position within the parent object)
  frag_total: uint16   (total fragments for this parent object)
  parent_id : bytes[8] (identifies the source object)
  data_len  : uint8    (payload length, 4-32)
  data      : bytes    (actual fragment payload)
"""

from __future__ import annotations
import os
import struct
import hashlib
import random
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Any, Optional

MIN_FRAG = 4
MAX_FRAG = 32


class FragType(IntEnum):
    SRVM = 0x01
    GTVM = 0x02
    NATV = 0x03
    WDOG = 0x04
    JUNK = 0xFF


@dataclass
class Fragment:
    frag_id:    int
    frag_type:  FragType
    frag_seq:   int          # position in parent
    frag_total: int          # total frags for parent
    parent_id:  bytes        # 8-byte parent identifier
    data:       bytes
    # runtime metadata (not serialised)
    source_label: str = ""   # human-readable source name

    # ── wire format ──────────────────────────────────────────────────────────
    # [4B frag_id][1B type][2B seq][2B total][8B parent_id][1B data_len][data]
    HEADER_SIZE = 18

    def serialise(self) -> bytes:
        return struct.pack('<IBHH8sB',
            self.frag_id,
            int(self.frag_type),
            self.frag_seq,
            self.frag_total,
            self.parent_id[:8],
            len(self.data),
        ) + self.data

    @classmethod
    def deserialise(cls, raw: bytes) -> "Fragment":
        fid, ftype, seq, total, pid, dlen = struct.unpack_from('<IBHH8sB', raw, 0)
        data = raw[cls.HEADER_SIZE : cls.HEADER_SIZE + dlen]
        return cls(frag_id=fid, frag_type=FragType(ftype),
                   frag_seq=seq, frag_total=total,
                   parent_id=pid, data=data)

    @property
    def wire_size(self) -> int:
        return self.HEADER_SIZE + len(self.data)


def _parent_id(label: str, index: int = 0) -> bytes:
    raw = f"{label}:{index}".encode()
    return hashlib.sha256(raw).digest()[:8]


def _split_bytes(
    data:       bytes,
    label:      str,
    frag_type:  FragType,
    start_id:   int,
    rng:        random.Random,
) -> List[Fragment]:
    """Split a byte blob into variable-length fragments."""
    chunks: List[bytes] = []
    off = 0
    while off < len(data):
        sz = rng.randint(MIN_FRAG, MAX_FRAG)
        chunk = data[off:off+sz]
        if chunk:
            chunks.append(chunk)
        off += sz

    pid    = _parent_id(label)
    total  = len(chunks)
    frags  = []
    for seq, chunk in enumerate(chunks):
        frags.append(Fragment(
            frag_id    = start_id + seq,
            frag_type  = frag_type,
            frag_seq   = seq,
            frag_total = total,
            parent_id  = pid,
            data       = chunk,
            source_label = label,
        ))
    return frags


class Fragmenter:
    """
    Converts all stage outputs into a unified fragment pool.
    """

    def __init__(self, seed: int = 0):
        self._rng = random.Random(seed)
        self._id  = 0

    def _next_id(self, n: int = 1) -> int:
        base = self._id
        self._id += n
        return base

    # ── SRVM fragments ────────────────────────────────────────────────────────

    def fragment_srvm_bundle(self, bundle_bytes: bytes) -> List[Fragment]:
        """Fragment the entire SRVM encrypted bundle."""
        base = self._next_id()
        frags = _split_bytes(bundle_bytes, "srvm_bundle",
                              FragType.SRVM, base, self._rng)
        self._id = base + len(frags)
        return frags

    # ── GTVM fragments ────────────────────────────────────────────────────────

    def fragment_gtvm_dags(
        self, enc_dags_bundle: bytes
    ) -> List[Fragment]:
        base  = self._next_id()
        frags = _split_bytes(enc_dags_bundle, "gtvm_dags",
                              FragType.GTVM, base, self._rng)
        self._id = base + len(frags)
        return frags

    # ── Native block fragments ────────────────────────────────────────────────

    def fragment_native_bundle(self, native_bundle: bytes) -> List[Fragment]:
        base  = self._next_id()
        frags = _split_bytes(native_bundle, "native_bundle",
                              FragType.NATV, base, self._rng)
        self._id = base + len(frags)
        return frags

    # ── Watchdog fragments ────────────────────────────────────────────────────

    def fragment_watchdog(self, wd_bundle: bytes) -> List[Fragment]:
        base  = self._next_id()
        frags = _split_bytes(wd_bundle, "watchdog",
                              FragType.WDOG, base, self._rng)
        self._id = base + len(frags)
        return frags

    # ── Junk fragments ────────────────────────────────────────────────────────

    def make_junk(self, n: int) -> List[Fragment]:
        frags = []
        for _ in range(n):
            sz   = self._rng.randint(MIN_FRAG, MAX_FRAG)
            data = bytes(self._rng.randint(0, 255) for _ in range(sz))
            frags.append(Fragment(
                frag_id    = self._next_id(1),
                frag_type  = FragType.JUNK,
                frag_seq   = 0,
                frag_total = 1,
                parent_id  = os.urandom(8),
                data       = data,
                source_label = "junk",
            ))
            self._id += 1
        return frags

    # ── Fragment all sources at once ──────────────────────────────────────────

    def fragment_all(
        self,
        srvm_bundle:   bytes,
        gtvm_bundle:   bytes,
        native_bundle: bytes,
        wd_bundle:     bytes,
        junk_ratio:    float = 0.4,
    ) -> "FragmentPool":
        pool = FragmentPool()

        pool.add(self.fragment_srvm_bundle(srvm_bundle),   "srvm")
        pool.add(self.fragment_gtvm_dags(gtvm_bundle),     "gtvm")
        pool.add(self.fragment_native_bundle(native_bundle),"natv")
        pool.add(self.fragment_watchdog(wd_bundle),        "wdog")

        n_real = len(pool.all_frags)
        n_junk = int(n_real * junk_ratio)
        pool.add(self.make_junk(n_junk), "junk")

        return pool


@dataclass
class FragmentPool:
    all_frags: List[Fragment]           = field(default_factory=list)
    by_type:   Dict[str, List[Fragment]] = field(default_factory=dict)

    def add(self, frags: List[Fragment], label: str):
        self.all_frags.extend(frags)
        self.by_type.setdefault(label, []).extend(frags)

    def stats(self) -> str:
        lines = [f"FragmentPool: {len(self.all_frags)} total fragments"]
        for lbl, frags in self.by_type.items():
            total_b = sum(f.wire_size for f in frags)
            lines.append(f"  {lbl:<10} {len(frags):5d} frags  {total_b:7d} bytes")
        return "\n".join(lines)
