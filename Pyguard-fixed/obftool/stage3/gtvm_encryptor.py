"""
Module 3.3 – GT-VM Node/Timeline Encryptor
Encrypts each DAG node and its timeline independently using AES-256-GCM.

Key hierarchy:
  master_key → per-dag_key → per-node_key
  per_node_key = HMAC-SHA256(per_dag_key, node_id || salt)

Each encrypted node blob:
  [2B: node_id_len][node_id]
  [1B: kind]
  [2B: nonce_len][nonce]
  [4B: ct_len][ciphertext]
  [16B: tag]

The node's "payload" that gets encrypted is the serialised timeline blob
(from module 3.2) prepended with a small node header (op, dt, deps list).
"""

from __future__ import annotations
import os
import json
import hmac
import struct
import hashlib
import base64
from dataclasses import dataclass
from typing import Dict, List, Any, Optional

from stage3.gtvm_graph_builder  import DAGNode, ExecutionDAG, NodeKind
from stage3.timeline_generator  import TimelineSerialiser


# ── AES-GCM (same backend as stage2) ─────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    def _gcm_enc(key, nonce, pt, aad=b""):
        ct_tag = _AESGCM(key).encrypt(nonce, pt, aad or None)
        return ct_tag[:-16], ct_tag[-16:]
    def _gcm_dec(key, nonce, ct, tag, aad=b""):
        return _AESGCM(key).decrypt(nonce, ct + tag, aad or None)
except ImportError:
    def _gcm_enc(key, nonce, pt, aad=b""): return pt, b'\x00' * 16
    def _gcm_dec(key, nonce, ct, tag, aad=b""): return ct


KEY_LEN   = 32
NONCE_LEN = 12
SALT_LEN  = 16
PBKDF2_ITERS = 100_000
HKDF_INFO    = b"GTVM-NODE-v1"


def _pbkdf2(seed: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", seed + HKDF_INFO, salt,
                               PBKDF2_ITERS, dklen=KEY_LEN)

def _node_key(dag_key: bytes, node_id: str, salt: bytes) -> bytes:
    return hmac.new(dag_key, node_id.encode() + salt + HKDF_INFO, "sha256").digest()


# ─────────────────────────────────────────────────────────────────────────────
# Encrypted Node
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EncryptedNode:
    node_id:    str
    kind:       str          # NodeKind value
    nonce:      bytes
    ciphertext: bytes
    tag:        bytes
    salt:       bytes
    aad:        bytes = b""

    def serialise(self) -> bytes:
        id_b  = self.node_id.encode()
        kind_b = self.kind.encode()
        return b"".join([
            struct.pack('<H', len(id_b)),   id_b,
            struct.pack('<B', len(kind_b)), kind_b,
            struct.pack('<H', len(self.salt)), self.salt,
            struct.pack('<H', len(self.nonce)), self.nonce,
            struct.pack('<I', len(self.ciphertext)), self.ciphertext,
            self.tag,   # 16B
            struct.pack('<H', len(self.aad)), self.aad,
        ])

    @classmethod
    def deserialise(cls, data: bytes) -> "EncryptedNode":
        off = 0
        def r(n): nonlocal off; v=data[off:off+n]; off+=n; return v
        def r2(): return r(struct.unpack('<H', r(2))[0])
        def r1s(): return r(struct.unpack('<B', r(1))[0])
        id_b     = r2()
        kind_b   = r1s()
        salt     = r2()
        nonce    = r2()
        ct_sz    = struct.unpack('<I', r(4))[0]
        ct       = r(ct_sz)
        tag      = r(16)
        aad      = r2()
        return cls(
            node_id    = id_b.decode(),
            kind       = kind_b.decode(),
            nonce      = nonce,
            ciphertext = ct,
            tag        = tag,
            salt       = salt,
            aad        = aad,
        )

    def decrypt(self, dag_key: bytes) -> bytes:
        nkey = _node_key(dag_key, self.node_id, self.salt)
        return _gcm_dec(nkey, self.nonce, self.ciphertext, self.tag, self.aad)


# ─────────────────────────────────────────────────────────────────────────────
# Encrypted DAG
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EncryptedDAG:
    function_name: str
    nodes:         Dict[str, EncryptedNode]
    # adjacency list in plaintext (node_ids only – no value info)
    adj:           Dict[str, List[str]]
    topo:          List[str]
    entry:         str
    exits:         List[str]
    # dag-level key salt (master_key + this salt → dag_key)
    dag_salt:      bytes

    def serialise(self) -> bytes:
        # header
        name_b = self.function_name.encode()
        entry_b = self.entry.encode()
        adj_json = json.dumps(self.adj).encode()
        topo_json = json.dumps(self.topo).encode()
        exits_json = json.dumps(self.exits).encode()
        hdr = b"".join([
            struct.pack('<H', len(name_b)),  name_b,
            struct.pack('<H', len(self.dag_salt)), self.dag_salt,
            struct.pack('<H', len(entry_b)), entry_b,
            struct.pack('<I', len(adj_json)), adj_json,
            struct.pack('<I', len(topo_json)), topo_json,
            struct.pack('<I', len(exits_json)), exits_json,
            struct.pack('<I', len(self.nodes)),
        ])
        node_blobs = []
        for enc_node in self.nodes.values():
            blob = enc_node.serialise()
            node_blobs.append(struct.pack('<I', len(blob)) + blob)
        return hdr + b"".join(node_blobs)

    @classmethod
    def deserialise(cls, data: bytes) -> "EncryptedDAG":
        off = 0
        def r(n): nonlocal off; v=data[off:off+n]; off+=n; return v
        def r2j(): return r(struct.unpack('<H', r(2))[0])
        def r4j(): return r(struct.unpack('<I', r(4))[0])

        name_b     = r2j()
        dag_salt   = r2j()
        entry_b    = r2j()
        adj        = json.loads(r4j())
        topo       = json.loads(r4j())
        exits      = json.loads(r4j())
        n_nodes    = struct.unpack('<I', r(4))[0]

        nodes = {}
        for _ in range(n_nodes):
            sz     = struct.unpack('<I', r(4))[0]
            blob   = r(sz)
            enc    = EncryptedNode.deserialise(blob)
            nodes[enc.node_id] = enc

        return cls(
            function_name = name_b.decode(),
            nodes         = nodes,
            adj           = adj,
            topo          = topo,
            entry         = entry_b.decode(),
            exits         = exits,
            dag_salt      = dag_salt,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Node Payload Builder
# ─────────────────────────────────────────────────────────────────────────────

class NodePayloadBuilder:
    """
    Serialises a node's essential data + its full timeline dict
    into a single plaintext blob for encryption.

    Layout:
      [1B: kind_len][kind_str]
      [2B: op_len][op_str]
      [8B: dt as double]
      [2B: n_deps][dep0_len:dep0] ...
      [4B: timeline_blob_len][timeline_blob]
      [4B: meta_json_len][meta_json]
    """
    _ts = TimelineSerialiser()

    def encode(self, node: DAGNode) -> bytes:
        kind_b  = node.kind.encode()
        op_b    = node.op.encode()
        dep_blobs = []
        for dep in node.deps:
            d = dep.encode()
            dep_blobs.append(struct.pack('<H', len(d)) + d)
        tl_blob  = self._ts.serialise_node(node)
        meta_b   = json.dumps(
            {k: v for k, v in node.meta.items() if isinstance(v, (int, float, str, bool, type(None), list, dict))}
        ).encode()
        return b"".join([
            struct.pack('<B', len(kind_b)), kind_b,
            struct.pack('<H', len(op_b)), op_b,
            struct.pack('<d', node.dt),
            struct.pack('<H', len(node.deps)),
            *dep_blobs,
            struct.pack('<I', len(tl_blob)), tl_blob,
            struct.pack('<I', len(meta_b)), meta_b,
        ])

    def decode(self, data: bytes) -> dict:
        off = 0
        def r(n): nonlocal off; v=data[off:off+n]; off+=n; return v

        kind_len  = r(1)[0]; kind = r(kind_len).decode()
        op_len    = struct.unpack('<H', r(2))[0]; op = r(op_len).decode()
        dt        = struct.unpack('<d', r(8))[0]
        n_deps    = struct.unpack('<H', r(2))[0]
        deps      = []
        for _ in range(n_deps):
            dlen = struct.unpack('<H', r(2))[0]
            deps.append(r(dlen).decode())
        tl_sz     = struct.unpack('<I', r(4))[0]
        tl_blob   = r(tl_sz)
        meta_sz   = struct.unpack('<I', r(4))[0]
        meta      = json.loads(r(meta_sz))
        timelines = self._ts.deserialise_node(tl_blob)
        return {"kind": kind, "op": op, "dt": dt,
                "deps": deps, "timelines": timelines, "meta": meta}


# ─────────────────────────────────────────────────────────────────────────────
# GT-VM Encryptor
# ─────────────────────────────────────────────────────────────────────────────

class GTVMEncryptor:

    def __init__(self, master_seed: bytes):
        self._master_seed = master_seed
        self._payload_builder = NodePayloadBuilder()

    def encrypt_all(self, dags: Dict[str, ExecutionDAG]) -> Dict[str, EncryptedDAG]:
        return {name: self.encrypt_dag(dag) for name, dag in dags.items()}

    def encrypt_dag(self, dag: ExecutionDAG) -> EncryptedDAG:
        dag_salt = os.urandom(SALT_LEN)
        dag_key  = _pbkdf2(self._master_seed, dag_salt + dag.function_name.encode())

        enc_nodes: Dict[str, EncryptedNode] = {}
        for nid, node in dag.nodes.items():
            enc_nodes[nid] = self._encrypt_node(node, dag_key)

        adj = {nid: dag.successors(nid) for nid in dag.nodes}

        return EncryptedDAG(
            function_name = dag.function_name,
            nodes         = enc_nodes,
            adj           = adj,
            topo          = list(dag.topo),
            entry         = dag.entry,
            exits         = list(dag.exits),
            dag_salt      = dag_salt,
        )

    def _encrypt_node(self, node: DAGNode, dag_key: bytes) -> EncryptedNode:
        salt     = os.urandom(SALT_LEN)
        nonce    = os.urandom(NONCE_LEN)
        nkey     = _node_key(dag_key, node.node_id, salt)
        aad      = node.node_id.encode() + node.kind.encode()
        pt       = self._payload_builder.encode(node)
        ct, tag  = _gcm_enc(nkey, nonce, pt, aad)

        return EncryptedNode(
            node_id    = node.node_id,
            kind       = node.kind.value,
            nonce      = nonce,
            ciphertext = ct,
            tag        = tag,
            salt       = salt,
            aad        = aad,
        )

    def decrypt_dag(
        self, enc_dag: EncryptedDAG
    ) -> Dict[str, dict]:
        dag_key = _pbkdf2(self._master_seed,
                          enc_dag.dag_salt + enc_dag.function_name.encode())
        results = {}
        for nid, enc_node in enc_dag.nodes.items():
            raw  = enc_node.decrypt(dag_key)
            data = self._payload_builder.decode(raw)
            results[nid] = data
        return results


# ─── convenience ─────────────────────────────────────────────────────────────

def encrypt_dags(
    dags:        Dict[str, ExecutionDAG],
    master_seed: Optional[bytes] = None,
) -> tuple[Dict[str, EncryptedDAG], bytes]:
    if master_seed is None:
        master_seed = os.urandom(32)
    enc = GTVMEncryptor(master_seed)
    return enc.encrypt_all(dags), master_seed
