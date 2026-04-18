"""
Module 7.1 – Payload Packer
Creates a binary payload bundle with structured header:

  [8B  magic        ]  b'PYGUARD1'
  [4B  version      ]  u32 = 1
  [4B  seed_lo      ]  lower 32 bits of interleave_seed
  [4B  seed_hi      ]  upper 32 bits
  [4B  graph_offset ]  byte offset to graph_blob within body
  [4B  graph_len    ]  byte length of graph_blob
  [4B  srvm_offset  ]  byte offset to srvm_bundle
  [4B  srvm_len     ]
  [4B  gtvm_offset  ]
  [4B  gtvm_len     ]
  [4B  natv_offset  ]
  [4B  natv_len     ]
  [4B  wd_offset    ]
  [4B  wd_len       ]
  [32B build_id_hash]  sha256 of build_id string
  [body: sections concatenated]
"""
from __future__ import annotations
import hashlib
import struct

MAGIC   = b"PYGUARD1"
VERSION = 1


class PayloadHeader:
    SIZE = 8 + 4 + 4 + 4 + (6 * 8) + 32  # 100 bytes

    def __init__(self, *, interleave_seed: int, build_id: str,
                 graph_offset: int, graph_len: int,
                 srvm_offset: int,  srvm_len:  int,
                 gtvm_offset: int,  gtvm_len:  int,
                 natv_offset: int,  natv_len:  int,
                 wd_offset:   int,  wd_len:    int):
        self.interleave_seed = interleave_seed
        self.build_id_hash   = hashlib.sha256(build_id.encode()).digest()
        self.graph_offset = graph_offset; self.graph_len = graph_len
        self.srvm_offset  = srvm_offset;  self.srvm_len  = srvm_len
        self.gtvm_offset  = gtvm_offset;  self.gtvm_len  = gtvm_len
        self.natv_offset  = natv_offset;  self.natv_len  = natv_len
        self.wd_offset    = wd_offset;    self.wd_len    = wd_len

    def serialise(self) -> bytes:
        seed_lo = self.interleave_seed & 0xFFFFFFFF
        seed_hi = (self.interleave_seed >> 32) & 0xFFFFFFFF
        return (
            MAGIC
            + struct.pack("<III", VERSION, seed_lo, seed_hi)
            + struct.pack("<II", self.graph_offset, self.graph_len)
            + struct.pack("<II", self.srvm_offset,  self.srvm_len)
            + struct.pack("<II", self.gtvm_offset,  self.gtvm_len)
            + struct.pack("<II", self.natv_offset,  self.natv_len)
            + struct.pack("<II", self.wd_offset,    self.wd_len)
            + self.build_id_hash
        )

    @classmethod
    def parse(cls, data: bytes) -> "PayloadHeader":
        assert data[:8] == MAGIC, "Bad magic"
        ver, seed_lo, seed_hi = struct.unpack_from("<III", data, 8)
        assert ver == VERSION
        seed = seed_lo | (seed_hi << 32)
        off = 20
        fields = struct.unpack_from("<IIIIIIIIII", data, off)
        bid_hash = data[off + 40: off + 72]
        h = cls.__new__(cls)
        h.interleave_seed = seed
        h.build_id_hash   = bid_hash
        h.graph_offset, h.graph_len = fields[0], fields[1]
        h.srvm_offset,  h.srvm_len  = fields[2], fields[3]
        h.gtvm_offset,  h.gtvm_len  = fields[4], fields[5]
        h.natv_offset,  h.natv_len  = fields[6], fields[7]
        h.wd_offset,    h.wd_len    = fields[8], fields[9]
        return h


class PackedPayload:
    def __init__(self, header: PayloadHeader, body: bytes):
        self.header = header
        self.body   = body

    def serialise(self) -> bytes:
        return self.header.serialise() + self.body

    @property
    def total_size(self) -> int:
        return PayloadHeader.SIZE + len(self.body)


def pack_payload(
    *,
    graph_blob:     bytes,
    srvm_bundle:    bytes,
    gtvm_bundle:    bytes,
    native_bundle:  bytes,
    wd_bundle:      bytes,
    interleave_seed: int,
    build_id:       str,
) -> PackedPayload:
    """
    Concatenate all bundles into a body, compute offsets, build header.
    """
    sections = [graph_blob, srvm_bundle, gtvm_bundle, native_bundle, wd_bundle]
    offsets  = []
    pos      = 0
    for s in sections:
        offsets.append(pos)
        pos += len(s)
    body = b"".join(sections)

    header = PayloadHeader(
        interleave_seed = interleave_seed,
        build_id        = build_id,
        graph_offset    = offsets[0], graph_len = len(graph_blob),
        srvm_offset     = offsets[1], srvm_len  = len(srvm_bundle),
        gtvm_offset     = offsets[2], gtvm_len  = len(gtvm_bundle),
        natv_offset     = offsets[3], natv_len  = len(native_bundle),
        wd_offset       = offsets[4], wd_len    = len(wd_bundle),
    )
    return PackedPayload(header, body)
