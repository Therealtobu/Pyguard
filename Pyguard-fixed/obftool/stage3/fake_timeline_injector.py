"""
Module 3.4 – Fake Timeline Injector
Injects "dead timelines" – entirely fake DAG subgraphs that look
structurally identical to real DAGs but are never executed at runtime.

Dead timelines serve as:
  1. Graph bloat – analyst can't quickly identify real execution paths
  2. Decoy nodes – fake nodes reference real node_ids in deps list
     (so the graph looks fully connected) but their outputs are discarded
  3. Value noise – fake timelines carry plausible but wrong values

Injection strategies:
  A. NODE DUPLICATION  – clone N real nodes with altered values, insert
     adjacent to real counterpart, wire decoy edges
  B. SUBGRAPH SHADOW   – clone a full basic-block-sized subgraph and
     add it as an alternate path (with never-taken conditional branch)
  C. ORPHAN CHAINS     – isolated 5-15 node chains that reference real
     node_ids in their deps but are unreachable from entry
"""

from __future__ import annotations
import os
import random
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

from stage3.gtvm_graph_builder import (
    DAGNode, DAGEdge, ExecutionDAG, NodeKind
)
from stage3.timeline_generator import _random_fake_value, N_FAKE_VERSIONS, DT_STEP


FAKE_INJECTION_RATIO = 0.35   # inject fake nodes up to 35% of original count
MIN_ORPHAN_CHAINS    = 2
MAX_ORPHAN_CHAINS    = 5
ORPHAN_CHAIN_LEN     = (5, 15)


class FakeTimelineInjector:

    def __init__(self, seed: int = 0, ratio: float = FAKE_INJECTION_RATIO):
        self._rng   = random.Random(seed)
        self._ratio = ratio
        self._ctr   = 0

    # ── public ────────────────────────────────────────────────────────────────

    def inject_all(self, dags: Dict[str, ExecutionDAG]) -> Dict[str, ExecutionDAG]:
        for dag in dags.values():
            self.inject(dag)
        return dags

    def inject(self, dag: ExecutionDAG) -> ExecutionDAG:
        n_real  = len(dag.nodes)
        n_fake  = max(3, int(n_real * self._ratio))

        # Strategy A: node duplication
        n_dup = n_fake // 3
        self._inject_node_dups(dag, n_dup)

        # Strategy B: subgraph shadows
        n_shadow = n_fake // 3
        self._inject_shadow_subgraphs(dag, n_shadow)

        # Strategy C: orphan chains
        n_chains = self._rng.randint(MIN_ORPHAN_CHAINS, MAX_ORPHAN_CHAINS)
        self._inject_orphan_chains(dag, n_chains)

        # Re-sort topo (fake nodes appended last)
        dag.topo = self._rebuild_topo(dag)
        return dag

    # ── Strategy A – node duplicates ─────────────────────────────────────────

    def _inject_node_dups(self, dag: ExecutionDAG, count: int):
        real_nodes = [n for n in dag.nodes.values()
                      if n.kind not in (NodeKind.ENTRY, NodeKind.EXIT)]
        if not real_nodes:
            return

        for _ in range(count):
            orig = self._rng.choice(real_nodes)
            fake = self._clone_fake(orig)
            dag.add_node(fake)
            # wire: same predecessors as original → fake  (dead branch)
            for dep in orig.deps:
                dag.add_edge(DAGEdge(src=dep, dst=fake.node_id,
                                     op=f"FAKE_{orig.op}",
                                     dt=orig.dt + 50.0,
                                     meta={"is_fake": True}))

    # ── Strategy B – shadow subgraphs ─────────────────────────────────────────

    def _inject_shadow_subgraphs(self, dag: ExecutionDAG, node_budget: int):
        """Clone a contiguous window of nodes as a shadow subgraph."""
        topo = dag.topo
        if len(topo) < 4:
            return
        window_size = min(node_budget, max(3, len(topo) // 5))
        if window_size < 2:
            return

        # Pick a random window
        start = self._rng.randint(0, max(0, len(topo) - window_size))
        window_nids = topo[start:start + window_size]
        window_nodes = [dag.nodes[nid] for nid in window_nids if nid in dag.nodes]

        id_remap: Dict[str, str] = {}
        for node in window_nodes:
            fake = self._clone_fake(node)
            id_remap[node.node_id] = fake.node_id
            dag.add_node(fake)

        # Remap edges within shadow
        for orig_node in window_nodes:
            fake_id = id_remap[orig_node.node_id]
            for dep in orig_node.deps:
                src = id_remap.get(dep, dep)  # keep external deps real
                dag.add_edge(DAGEdge(src=src, dst=fake_id,
                                     op=f"SHADOW_{orig_node.op}",
                                     dt=orig_node.dt + 100.0,
                                     meta={"is_fake": True}))

    # ── Strategy C – orphan chains ────────────────────────────────────────────

    def _inject_orphan_chains(self, dag: ExecutionDAG, n_chains: int):
        real_nids = list(dag.nodes.keys())

        for _ in range(n_chains):
            chain_len = self._rng.randint(*ORPHAN_CHAIN_LEN)
            prev_id   = None
            ops       = ["ADD", "SUB", "MUL", "LOAD_NAME", "LOAD_CONST",
                         "STORE_NAME", "CALL", "EQ", "AND", "NOT"]

            for i in range(chain_len):
                nid  = self._fake_id(f"orphan_{i}")
                op   = self._rng.choice(ops)
                kind = NodeKind.OP if op not in ("RETURN", "JUMP") else NodeKind.CTRL
                # Reference a real dep to look connected
                real_dep = self._rng.choice(real_nids) if real_nids else None
                deps     = ([real_dep] if real_dep and i == 0 else
                            [prev_id]  if prev_id else [])

                node = DAGNode(
                    node_id  = nid,
                    kind     = kind,
                    op       = op,
                    dt       = 200.0 + i * DT_STEP,
                    deps     = deps,
                    meta     = {"is_fake": True, "orphan": True},
                )
                node.timelines = self._fake_timelines(node)
                dag.add_node(node)

                if prev_id:
                    dag.add_edge(DAGEdge(src=prev_id, dst=nid,
                                         op=op, dt=0.05,
                                         meta={"is_fake": True}))
                prev_id = nid

    # ── helpers ───────────────────────────────────────────────────────────────

    def _clone_fake(self, orig: DAGNode) -> DAGNode:
        nid  = self._fake_id(orig.op)
        fake_val = _random_fake_value(self._rng)
        node = DAGNode(
            node_id  = nid,
            kind     = orig.kind,
            op       = orig.op,
            value    = fake_val,
            name     = orig.name,
            dt       = orig.dt + 50.0,
            deps     = list(orig.deps),
            meta     = dict(orig.meta) | {"is_fake": True},
        )
        node.timelines = self._fake_timelines(node)
        return node

    def _fake_timelines(self, node: DAGNode) -> Dict[str, Dict]:
        tls = {}
        fake_val = _random_fake_value(self._rng)
        tls["t0"] = {
            "value":  fake_val,
            "active": True,   # looks active – but this node is never reached
            "dt":     node.dt,
            "is_fake": True,
        }
        for j in range(N_FAKE_VERSIONS):
            tls[f"t_fake_{j}"] = {
                "value":  _random_fake_value(self._rng),
                "active": False,
                "dt":     node.dt + 99.0 + j * DT_STEP,
                "is_fake": True,
            }
        return tls

    def _fake_id(self, hint: str = "") -> str:
        self._ctr += 1
        h = hashlib.sha1(f"FAKE:{self._ctr}:{hint}:{self._rng.random()}".encode()).hexdigest()[:8]
        return f"F{self._ctr:05d}_{h}"

    def _rebuild_topo(self, dag: ExecutionDAG) -> List[str]:
        """Append any new nodes not in existing topo."""
        existing = set(dag.topo)
        new_nodes = [nid for nid in dag.nodes if nid not in existing]
        return dag.topo + new_nodes


# ─── convenience ─────────────────────────────────────────────────────────────

def inject_fake_timelines(
    dags: Dict[str, ExecutionDAG],
    seed: int = 0,
    ratio: float = FAKE_INJECTION_RATIO,
) -> Dict[str, ExecutionDAG]:
    injector = FakeTimelineInjector(seed=seed, ratio=ratio)
    return injector.inject_all(dags)
