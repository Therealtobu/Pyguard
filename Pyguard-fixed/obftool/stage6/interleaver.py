"""
Module 6.2 – Stateful Interleaver
Shuffles the fragment pool into a final ordered sequence using a
deterministic seed-based algorithm.  The shuffle order is reproducible
from the seed stored in the payload header.

Algorithm:
  1. Partition fragments by type: real (SRVM/GTVM/NATV/WDOG) and junk
  2. Interleave junk among real fragments according to the seed
  3. Apply a Fisher-Yates shuffle over the entire sequence
  4. Record the final ordering as an index list saved in the graph header

Module 6.3 – Tag Generator
Assigns a positional tag to each fragment in the interleaved sequence.

Tag structure (24 bytes):
  [4B: frag_id]
  [1B: frag_type]
  [2B: frag_seq]
  [2B: frag_total]
  [8B: parent_id]
  [4B: next_index]     ← index of next fragment in same parent chain
  [2B: checksum]       ← CRC16 of tag bytes 0-21
  [1B: xor_key]        ← position-dependent XOR key (tag bytes XOR'd)

Tags are stored in a separate tag table (encrypted by 6.5 key derivation).
"""

from __future__ import annotations
import os
import struct
import random
import hashlib
from typing import Dict, List, Optional, Tuple

from stage6.fragmenter import Fragment, FragmentPool, FragType


# ═════════════════════════════════════════════════════════════════════════════
# 6.2 – Stateful Interleaver
# ═════════════════════════════════════════════════════════════════════════════

class StatefulInterleaver:
    """
    Produces a deterministic interleaved sequence from a FragmentPool.
    The seed is stored in the final payload header so the loader can
    reconstruct the correct ordering.
    """

    def __init__(self, seed: Optional[int] = None):
        if seed is None:
            seed = int.from_bytes(os.urandom(8), 'little')
        self._seed = seed
        self._rng  = random.Random(seed)

    @property
    def seed(self) -> int:
        return self._seed

    def interleave(self, pool: FragmentPool) -> List[Fragment]:
        real = [f for f in pool.all_frags if f.frag_type != FragType.JUNK]
        junk = [f for f in pool.all_frags if f.frag_type == FragType.JUNK]

        # Step 1: sort real fragments so same-parent frags are adjacent
        real.sort(key=lambda f: (f.parent_id, f.frag_seq))

        # Step 2: interleave junk at random positions
        result: List[Fragment] = list(real)
        junk_positions = sorted(
            self._rng.sample(range(len(result) + len(junk)), len(junk))
        )
        for pos, j_frag in zip(junk_positions, junk):
            result.insert(pos, j_frag)

        # Step 3: Fisher-Yates shuffle with seed-derived RNG
        # (full shuffle makes static ordering analysis infeasible)
        shuffle_rng = random.Random(self._seed ^ 0xDEADBEEF)
        for i in range(len(result) - 1, 0, -1):
            j = shuffle_rng.randint(0, i)
            result[i], result[j] = result[j], result[i]

        return result

    def seed_bytes(self) -> bytes:
        return struct.pack('<Q', self._seed)


# ═════════════════════════════════════════════════════════════════════════════
# 6.3 – Tag Generator
# ═════════════════════════════════════════════════════════════════════════════

TAG_SIZE = 24   # bytes


def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc & 0xFFFF


def _position_xor_key(position: int, global_seed: int) -> int:
    """Derives a 1-byte XOR key from fragment position + global seed."""
    raw = struct.pack('<QI', global_seed, position)
    return hashlib.sha256(raw).digest()[0]


class TaggedFragment:
    """A fragment + its 24-byte encrypted tag."""
    __slots__ = ("fragment", "tag_plain", "tag_enc", "position")

    def __init__(self, fragment: Fragment, tag_plain: bytes,
                 tag_enc: bytes, position: int):
        self.fragment  = fragment
        self.tag_plain = tag_plain
        self.tag_enc   = tag_enc
        self.position  = position

    def serialise(self) -> bytes:
        """[TAG_SIZE bytes tag][fragment.wire_size bytes frag]"""
        return self.tag_enc + self.fragment.serialise()


class TagGenerator:
    """
    Assigns positional tags to an ordered fragment sequence.

    Tag layout (plain, before XOR):
      [4B: frag_id]
      [1B: frag_type]
      [2B: frag_seq]
      [2B: frag_total]
      [8B: parent_id]
      [4B: next_index]   ← position of next same-parent fragment (-1 if last)
      [2B: crc16]        ← over bytes 0-21
      [1B: xor_key]      ← the key used to encrypt this tag
    """

    def __init__(self, global_seed: int):
        self._gseed = global_seed

    def tag_sequence(self, ordered: List[Fragment]) -> List[TaggedFragment]:
        # Build next_index map: frag_id → position of next sibling
        # siblings = fragments with same parent_id, ordered by frag_seq
        parent_positions: Dict[bytes, Dict[int, int]] = {}
        for pos, frag in enumerate(ordered):
            if frag.frag_type == FragType.JUNK:
                continue
            pid = frag.parent_id
            parent_positions.setdefault(pid, {})[frag.frag_seq] = pos

        def next_idx(frag: Fragment, pos: int) -> int:
            if frag.frag_type == FragType.JUNK:
                return 0xFFFFFFFF
            siblings = parent_positions.get(frag.parent_id, {})
            next_seq = frag.frag_seq + 1
            return siblings.get(next_seq, 0xFFFFFFFF)

        tagged = []
        for pos, frag in enumerate(ordered):
            nidx     = next_idx(frag, pos)
            plain    = self._make_tag_plain(frag, pos, nidx)
            xor_key  = _position_xor_key(pos, self._gseed)
            enc      = self._xor_tag(plain, xor_key)
            tagged.append(TaggedFragment(frag, plain, enc, pos))

        return tagged

    def _make_tag_plain(
        self, frag: Fragment, pos: int, next_idx: int
    ) -> bytes:
        # bytes 0-21 (22 bytes)
        body = struct.pack('<IBHH8sI',
            frag.frag_id,
            int(frag.frag_type),
            frag.frag_seq,
            frag.frag_total,
            frag.parent_id[:8],
            next_idx,
        )
        crc   = _crc16(body)
        xk    = _position_xor_key(pos, self._gseed)
        # bytes 22-23
        tail  = struct.pack('<HB', crc, xk)
        return body + tail  # 22 + 2 + ... wait: 4+1+2+2+8+4 = 21, then 2+1 = 3 → 24 total

    def _xor_tag(self, plain: bytes, xor_key: int) -> bytes:
        return bytes(b ^ xor_key for b in plain)

    # ── tag table serialisation ───────────────────────────────────────────────

    def serialise_tag_table(self, tagged: List[TaggedFragment]) -> bytes:
        """
        Compact tag table:
          [4B: n_tags]
          [n_tags × TAG_SIZE: encrypted tags in sequence order]
        """
        pieces = [struct.pack('<I', len(tagged))]
        for tf in tagged:
            pieces.append(tf.tag_enc)
        return b"".join(pieces)

    @staticmethod
    def decode_tag(enc_tag: bytes, position: int, global_seed: int) -> dict:
        xor_key = _position_xor_key(position, global_seed)
        plain   = bytes(b ^ xor_key for b in enc_tag)
        frag_id, ftype, seq, total, pid, nidx = struct.unpack_from('<IBHH8sI', plain)
        crc_stored = struct.unpack_from('<H', plain, 21)[0]
        crc_calc   = _crc16(plain[:21])
        return {
            "frag_id":    frag_id,
            "frag_type":  ftype,
            "frag_seq":   seq,
            "frag_total": total,
            "parent_id":  pid,
            "next_index": nidx,
            "crc_ok":     crc_stored == crc_calc,
        }
