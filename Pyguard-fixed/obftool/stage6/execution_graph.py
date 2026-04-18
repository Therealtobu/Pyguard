"""
Module 6.4 – Execution Graph Builder
Builds a directed execution graph from the interleaved fragment sequence.

Each fragment → graph node.
Edges:
  • Sequential edge: node[i] → node[i+1]  (normal flow)
  • Parent-chain edge: node → next_sibling (from tag.next_index)
  • Conditional edges: for CTRL-type fragments (CJUMP analogue)

The graph is stored as:
  - Adjacency list: {node_index: [successor_indices]}
  - Node types: {node_index: {"type", "parent_id", "frag_type", "seq", ...}}
  - Entry point: index 0

Module 6.5 – Per-Node Key Derivation
Derives an independent AES-256-GCM key for every graph node using:
  K_node = HMAC-SHA256(master_key, node_id_bytes || node_index || salt)

Nodes are then re-encrypted with their per-node key so no two nodes
share the same key (limits blast radius of any single key leak).
"""

from __future__ import annotations
import os
import hmac
import struct
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from stage6.fragmenter  import Fragment, FragType
from stage6.interleaver import TaggedFragment, TagGenerator

# ── AES-GCM backend ───────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    def _gcm_enc(k, n, pt, aad=b""):
        ct_tag = _AESGCM(k).encrypt(n, pt, aad or None)
        return ct_tag[:-16], ct_tag[-16:]
    def _gcm_dec(k, n, ct, tag, aad=b""):
        return _AESGCM(k).decrypt(n, ct+tag, aad or None)
except ImportError:
    def _gcm_enc(k, n, pt, aad=b""): return pt, b'\x00'*16
    def _gcm_dec(k, n, ct, tag, aad=b""): return ct

KEY_LEN   = 32
NONCE_LEN = 12
SALT_LEN  = 16
HKDF_INFO = b"EXECGRAPH-NODE-v1"


# ═════════════════════════════════════════════════════════════════════════════
# 6.4 – Execution Graph Builder
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class GraphNode:
    index:      int
    frag_id:    int
    frag_type:  int
    frag_seq:   int
    frag_total: int
    parent_id:  bytes
    is_junk:    bool
    successors: List[int]          = field(default_factory=list)
    predecessors: List[int]        = field(default_factory=list)
    meta:       Dict               = field(default_factory=dict)
    # filled by 6.5
    node_key:   Optional[bytes]    = None
    enc_data:   Optional[bytes]    = None
    enc_tag:    Optional[bytes]    = None
    enc_nonce:  Optional[bytes]    = None
    node_salt:  Optional[bytes]    = None


@dataclass
class ExecutionGraph:
    nodes:   Dict[int, GraphNode]   = field(default_factory=dict)
    entry:   int                    = 0
    n_real:  int                    = 0
    n_junk:  int                    = 0
    interleave_seed: int            = 0
    global_tag_seed: int            = 0

    def add_node(self, node: GraphNode):
        self.nodes[node.index] = node

    def add_edge(self, src: int, dst: int):
        sn = self.nodes.get(src)
        dn = self.nodes.get(dst)
        if sn and dst not in sn.successors:
            sn.successors.append(dst)
        if dn and src not in dn.predecessors:
            dn.predecessors.append(src)

    def adjacency(self) -> Dict[int, List[int]]:
        return {idx: list(node.successors) for idx, node in self.nodes.items()}

    def stats(self) -> str:
        n_edges = sum(len(n.successors) for n in self.nodes.values())
        return (f"ExecutionGraph: {len(self.nodes)} nodes "
                f"({self.n_real} real / {self.n_junk} junk), "
                f"{n_edges} edges")


class ExecutionGraphBuilder:
    """
    Constructs the ExecutionGraph from a tagged fragment sequence.
    """

    def build(
        self,
        tagged:          List[TaggedFragment],
        interleave_seed: int,
        global_tag_seed: int,
    ) -> ExecutionGraph:
        graph = ExecutionGraph(
            entry            = 0,
            interleave_seed  = interleave_seed,
            global_tag_seed  = global_tag_seed,
        )

        # Step 1: create one node per tagged fragment
        parent_last_node: Dict[bytes, int] = {}  # parent_id → last seen index

        for tf in tagged:
            f    = tf.fragment
            idx  = tf.position
            node = GraphNode(
                index      = idx,
                frag_id    = f.frag_id,
                frag_type  = int(f.frag_type),
                frag_seq   = f.frag_seq,
                frag_total = f.frag_total,
                parent_id  = f.parent_id,
                is_junk    = f.frag_type == FragType.JUNK,
            )
            graph.add_node(node)
            if f.frag_type != FragType.JUNK:
                if f.frag_seq == 0:
                    parent_last_node[f.parent_id] = idx
                else:
                    parent_last_node[f.parent_id] = idx

        graph.n_real = sum(1 for n in graph.nodes.values() if not n.is_junk)
        graph.n_junk = sum(1 for n in graph.nodes.values() if n.is_junk)

        # Step 2: sequential edges i → i+1
        indices = sorted(graph.nodes.keys())
        for i in range(len(indices) - 1):
            graph.add_edge(indices[i], indices[i + 1])

        # Step 3: parent-chain edges (frag_seq → frag_seq+1 within same parent)
        self._wire_parent_chains(graph, tagged)

        # Step 4: conditional branch edges for CTRL-type fragments
        # (fragments that are control-flow markers get extra branch edges)
        self._wire_conditionals(graph, tagged)

        return graph

    def _wire_parent_chains(
        self,
        graph:  ExecutionGraph,
        tagged: List[TaggedFragment],
    ):
        # Build seq→position map per parent
        by_parent: Dict[bytes, Dict[int, int]] = {}
        for tf in tagged:
            f = tf.fragment
            if f.frag_type != FragType.JUNK:
                by_parent.setdefault(f.parent_id, {})[f.frag_seq] = tf.position

        for pid, seq_map in by_parent.items():
            seqs = sorted(seq_map)
            for i in range(len(seqs) - 1):
                src_pos = seq_map[seqs[i]]
                dst_pos = seq_map[seqs[i + 1]]
                graph.add_edge(src_pos, dst_pos)

    def _wire_conditionals(
        self,
        graph:  ExecutionGraph,
        tagged: List[TaggedFragment],
    ):
        """
        WDOG fragments get an extra edge to the first SRVM fragment
        (watchdog can redirect execution to VM entry on failure).
        NATV fragments get an edge back to SRVM fallback entry.
        """
        srvm_first: Optional[int] = None
        wdog_nodes: List[int]     = []
        natv_nodes: List[int]     = []

        for tf in tagged:
            f = tf.fragment
            if f.frag_type == FragType.SRVM and f.frag_seq == 0:
                srvm_first = tf.position
            elif f.frag_type == FragType.WDOG:
                wdog_nodes.append(tf.position)
            elif f.frag_type == FragType.NATV:
                natv_nodes.append(tf.position)

        if srvm_first is None:
            return
        for pos in wdog_nodes[:3]:   # limit extra edges
            graph.add_edge(pos, srvm_first)
        for pos in natv_nodes[:3]:
            graph.add_edge(pos, srvm_first)


# ═════════════════════════════════════════════════════════════════════════════
# 6.5 – Per-Node Key Derivation + Node Re-encryption
# ═════════════════════════════════════════════════════════════════════════════

class NodeKeyDeriver:
    """
    K_node = HMAC-SHA256(master_key, node_id || position_bytes || salt)
    where node_id = HMAC-SHA256(parent_id || frag_seq, master_key)[:8]
    """

    def __init__(self, master_key: bytes):
        self._master = master_key

    def derive(self, node: GraphNode) -> bytes:
        node_id = hmac.new(
            self._master,
            node.parent_id + struct.pack('<H', node.frag_seq) + HKDF_INFO,
            "sha256",
        ).digest()[:8]
        salt = node.node_salt or os.urandom(SALT_LEN)
        key  = hmac.new(
            self._master,
            node_id + struct.pack('<I', node.index) + salt + HKDF_INFO,
            "sha256",
        ).digest()
        return key


class NodeReencryptor:
    """
    Re-encrypts each GraphNode's fragment data with its own derived key.

    Before this stage the fragment data is the raw (already AES-GCM encrypted
    by stage 2/3/4/5) bytes.  This adds a second encryption layer so each
    node in the graph has a unique key.
    """

    def __init__(self, master_key: bytes):
        self._master  = master_key
        self._deriver = NodeKeyDeriver(master_key)

    def encrypt_graph(
        self,
        graph:  ExecutionGraph,
        tagged: List[TaggedFragment],
    ) -> ExecutionGraph:
        tf_by_pos = {tf.position: tf for tf in tagged}

        for idx, node in graph.nodes.items():
            tf = tf_by_pos.get(idx)
            if tf is None:
                continue
            plain_frag = tf.fragment.serialise()   # already encrypted payload
            node.node_salt = os.urandom(SALT_LEN)
            node.node_key  = self._deriver.derive(node)
            nonce = os.urandom(NONCE_LEN)
            aad   = self._node_aad(node)
            ct, tag = _gcm_enc(node.node_key, nonce, plain_frag, aad)
            node.enc_data  = ct
            node.enc_tag   = tag
            node.enc_nonce = nonce

        return graph

    def _node_aad(self, node: GraphNode) -> bytes:
        return struct.pack('<IiHH',
            node.index, node.frag_type,
            node.frag_seq, node.frag_total,
        ) + node.parent_id[:8]


# ═════════════════════════════════════════════════════════════════════════════
# Execution Graph Serialiser
# ═════════════════════════════════════════════════════════════════════════════

GRAPH_MAGIC = b"EXGR\x01\x00"


class ExecutionGraphSerialiser:
    """
    Serialises the encrypted ExecutionGraph into a single binary blob.

    Blob layout:
      [6B: magic]
      [8B: interleave_seed]
      [8B: global_tag_seed]
      [4B: n_nodes]
      [4B: n_real]
      [4B: n_junk]
      for each node (sorted by index):
        [4B: index]
        [1B: frag_type]
        [2B: frag_seq]
        [2B: frag_total]
        [8B: parent_id]
        [1B: is_junk]
        [1B: n_successors]
        [n_successors × 4B: successor indices]
        [2B: salt_len][salt]
        [2B: nonce_len][nonce]
        [4B: enc_data_len][enc_data]
        [16B: enc_tag]
      [4B: tag_table_len][tag_table_bytes]
      [4B: adj_json_len][adj_json]
    """

    def serialise(
        self,
        graph:     ExecutionGraph,
        tag_table: bytes,
    ) -> bytes:
        pieces = [
            GRAPH_MAGIC,
            struct.pack('<Q', graph.interleave_seed),
            struct.pack('<Q', graph.global_tag_seed),
            struct.pack('<III', len(graph.nodes), graph.n_real, graph.n_junk),
        ]

        for idx in sorted(graph.nodes):
            node = graph.nodes[idx]
            succs = node.successors[:255]  # cap at 255 successors
            node_b = struct.pack('<IBHH8sB',
                node.index,
                node.frag_type,
                node.frag_seq,
                node.frag_total,
                node.parent_id[:8],
                int(node.is_junk),
            )
            succ_b = struct.pack('<B', len(succs)) + \
                     b"".join(struct.pack('<I', s) for s in succs)

            salt  = node.node_salt or b""
            nonce = node.enc_nonce or b""
            data  = node.enc_data  or b""
            tag   = node.enc_tag   or b'\x00'*16

            node_blob = b"".join([
                node_b, succ_b,
                struct.pack('<H', len(salt)),  salt,
                struct.pack('<H', len(nonce)), nonce,
                struct.pack('<I', len(data)),  data,
                tag,
            ])
            pieces.append(struct.pack('<I', len(node_blob)))
            pieces.append(node_blob)

        # Tag table
        pieces.append(struct.pack('<I', len(tag_table)))
        pieces.append(tag_table)

        # Adjacency JSON (for loader)
        adj   = {str(k): v for k, v in graph.adjacency().items()}
        adj_b = json.dumps(adj).encode()
        pieces.append(struct.pack('<I', len(adj_b)))
        pieces.append(adj_b)

        return b"".join(pieces)

    def deserialise(self, data: bytes) -> dict:
        """Returns raw dict (deserialisation done by C loader at runtime)."""
        assert data[:6] == GRAPH_MAGIC, "Bad execution graph magic"
        off = 6
        iseed, gseed = struct.unpack_from('<QQ', data, off); off += 16
        n_nodes, n_real, n_junk = struct.unpack_from('<III', data, off); off += 12
        nodes = []
        for _ in range(n_nodes):
            blob_sz = struct.unpack_from('<I', data, off)[0]; off += 4
            blob    = data[off:off+blob_sz]; off += blob_sz
            nodes.append(blob)  # raw blobs for loader
        tt_sz  = struct.unpack_from('<I', data, off)[0]; off += 4
        tt     = data[off:off+tt_sz]; off += tt_sz
        adj_sz = struct.unpack_from('<I', data, off)[0]; off += 4
        adj    = json.loads(data[off:off+adj_sz])
        return {"interleave_seed": iseed, "global_tag_seed": gseed,
                "n_nodes": n_nodes, "n_real": n_real, "n_junk": n_junk,
                "nodes_raw": nodes, "tag_table": tt, "adjacency": adj}


# ─── convenience ─────────────────────────────────────────────────────────────

def build_execution_graph(
    tagged:          List[TaggedFragment],
    interleave_seed: int,
    global_tag_seed: int,
    master_key:      bytes,
) -> tuple[ExecutionGraph, bytes]:
    """
    Full 6.4→6.5 pipeline.
    Returns (encrypted_graph, graph_blob).
    """
    builder    = ExecutionGraphBuilder()
    graph      = builder.build(tagged, interleave_seed, global_tag_seed)

    reencryptor = NodeReencryptor(master_key)
    graph       = reencryptor.encrypt_graph(graph, tagged)

    tag_gen    = TagGenerator(global_tag_seed)
    tag_table  = tag_gen.serialise_tag_table(tagged)

    serialiser = ExecutionGraphSerialiser()
    graph_blob = serialiser.serialise(graph, tag_table)

    return graph, graph_blob
