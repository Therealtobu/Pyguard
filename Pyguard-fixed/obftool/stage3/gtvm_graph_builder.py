"""
Module 3.1 – GT-VM Graph Builder
Converts IR_shadow into an execution DAG where:
  • Nodes  = values / computational states (SSA-like)
  • Edges  = operations with a temporal displacement dt
             (dt = relative "time step" for timeline scheduling)

Each node carries:
  node_id   : str   (unique, derived from value + position)
  kind      : NodeKind  (CONST, NAME, OP, PHI, CTRL, ENTRY, EXIT)
  op        : str   (opcode name)
  value     : Any   (for CONST nodes)
  name      : str   (for NAME nodes)
  dt        : float (temporal displacement from predecessor)
  deps      : list[str]  (list of node_ids this node depends on)
  meta      : dict

Edges are stored as adjacency list: DAGEdge(src, dst, op, dt, meta).
"""

from __future__ import annotations
import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Any, Set, Tuple

from common.ir import (
    IROpcode, IRInstruction, IRFunction, IRModule
)


# ─────────────────────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────────────────────

class NodeKind(str, Enum):
    CONST  = "CONST"   # constant value
    NAME   = "NAME"    # variable / env lookup
    OP     = "OP"      # computational operation
    PHI    = "PHI"     # merge point (control flow join)
    CTRL   = "CTRL"    # control-flow only (JUMP, RETURN, RAISE)
    ENTRY  = "ENTRY"   # function entry sentinel
    EXIT   = "EXIT"    # function exit sentinel


@dataclass
class DAGNode:
    node_id:  str
    kind:     NodeKind
    op:       str              = ""
    value:    Any              = None
    name:     str              = ""
    dt:       float            = 0.0    # temporal displacement
    deps:     List[str]        = field(default_factory=list)   # predecessor node_ids
    meta:     Dict[str, Any]   = field(default_factory=dict)
    # timeline version slots (filled by Module 3.2)
    timelines: Dict[str, Any]  = field(default_factory=dict)
    # encryption state (filled by Module 3.3)
    encrypted: bool            = False


@dataclass
class DAGEdge:
    src:   str          # source node_id
    dst:   str          # destination node_id
    op:    str          # operation label
    dt:    float        = 0.0
    meta:  Dict         = field(default_factory=dict)


@dataclass
class ExecutionDAG:
    function_name: str
    nodes:  Dict[str, DAGNode] = field(default_factory=dict)
    edges:  List[DAGEdge]      = field(default_factory=list)
    entry:  str                = ""
    exits:  List[str]          = field(default_factory=list)
    # topological order (set by builder)
    topo:   List[str]          = field(default_factory=list)

    def add_node(self, node: DAGNode):
        self.nodes[node.node_id] = node

    def add_edge(self, e: DAGEdge):
        self.edges.append(e)

    def successors(self, nid: str) -> List[str]:
        return [e.dst for e in self.edges if e.src == nid]

    def predecessors(self, nid: str) -> List[str]:
        return [e.src for e in self.edges if e.dst == nid]


# ─────────────────────────────────────────────────────────────────────────────
# Builder
# ─────────────────────────────────────────────────────────────────────────────

class GTVMGraphBuilder:
    """
    Single-pass IR → DAG conversion.
    Maintains a virtual register map (tmp → node_id) and a name map
    (var_name → node_id) to wire dependencies.
    """

    _DT_BASE  = 1.0    # base temporal step per instruction
    _DT_CTRL  = 0.5    # control-flow edges have smaller dt (sequence-breakers)
    _DT_MERGE = 0.1    # PHI node dt (near-zero, represents merge)

    def __init__(self):
        self._counter   = 0
        self._tmp_nodes: Dict[str, str]  = {}   # tmp_var → node_id
        self._name_nodes: Dict[str, str] = {}   # env_name → node_id
        self._dag: Optional[ExecutionDAG] = None
        self._current_dt = 0.0

    # ── public ────────────────────────────────────────────────────────────────

    def build_all(self, module: IRModule) -> Dict[str, ExecutionDAG]:
        dags: Dict[str, ExecutionDAG] = {}
        for fn_name, fn in module.functions.items():
            dags[fn_name] = self.build_function(fn_name, fn)
        for cls in module.classes.values():
            for mname, method in cls.methods.items():
                key = f"{cls.name}.{mname}"
                dags[key] = self.build_function(key, method)
        # Module body
        dags["<module>"] = self._build_instrs("<module>", module.module_instrs)
        return dags

    def build_function(self, fn_name: str, fn: IRFunction) -> ExecutionDAG:
        instrs = fn.flat_instructions()
        return self._build_instrs(fn_name, instrs)

    def _build_instrs(self, name: str, instrs: List[IRInstruction]) -> ExecutionDAG:
        self._counter    = 0
        self._tmp_nodes  = {}
        self._name_nodes = {}
        self._current_dt = 0.0

        dag         = ExecutionDAG(function_name=name)
        self._dag   = dag

        # Entry node
        entry_id     = self._node_id("entry")
        entry_node   = DAGNode(node_id=entry_id, kind=NodeKind.ENTRY, op="ENTRY", dt=0.0)
        dag.add_node(entry_node)
        dag.entry    = entry_id
        self._prev   = entry_id

        for instr in instrs:
            self._convert(instr)

        # Exit node
        exit_id   = self._node_id("exit")
        exit_node = DAGNode(node_id=exit_id, kind=NodeKind.EXIT, op="EXIT",
                            dt=self._DT_CTRL)
        dag.add_node(exit_node)
        dag.exits.append(exit_id)
        # wire last CTRL node → EXIT
        dag.add_edge(DAGEdge(src=self._prev, dst=exit_id, op="EXIT",
                             dt=self._DT_CTRL))

        # Compute topological order
        dag.topo = self._topo_sort(dag)
        return dag

    # ── IR instruction → DAG node ─────────────────────────────────────────────

    def _convert(self, instr: IRInstruction):
        op = instr.op
        self._current_dt += self._DT_BASE

        # ── LABEL ────────────────────────────────────────────────────────────
        if op is IROpcode.LABEL:
            lbl_id = self._node_id(f"lbl_{instr.meta.get('name','')}")
            node   = DAGNode(node_id=lbl_id, kind=NodeKind.CTRL, op="LABEL",
                             dt=self._DT_MERGE,
                             meta={"label": instr.meta.get("name")})
            self._add(node, deps=[self._prev])
            self._prev = lbl_id
            return

        # ── LOAD_CONST ───────────────────────────────────────────────────────
        elif op is IROpcode.LOAD_CONST:
            val   = instr.meta.get("value")
            nid   = self._node_id(f"const_{repr(val)}")
            node  = DAGNode(node_id=nid, kind=NodeKind.CONST, op="CONST",
                            value=val, dt=self._current_dt)
            self._add(node, deps=[])
            self._set_tmp(instr.dest, nid)

        # ── LOAD_NAME ────────────────────────────────────────────────────────
        elif op is IROpcode.LOAD_NAME:
            var   = instr.src1 or instr.dest
            dep   = self._name_nodes.get(var)
            nid   = self._node_id(f"ld_{var}")
            node  = DAGNode(node_id=nid, kind=NodeKind.NAME, op="LOAD_NAME",
                            name=var, dt=self._current_dt,
                            deps=[dep] if dep else [self._prev])
            self._add(node, deps=[dep] if dep else [self._prev])
            self._set_tmp(instr.dest, nid)

        # ── STORE_NAME ───────────────────────────────────────────────────────
        elif op is IROpcode.STORE_NAME:
            src_nid = self._get_src(instr.src1)
            nid     = self._node_id(f"st_{instr.dest}")
            node    = DAGNode(node_id=nid, kind=NodeKind.OP, op="STORE_NAME",
                              name=instr.dest, dt=self._current_dt,
                              deps=[src_nid, self._prev])
            self._add(node, deps=[src_nid, self._prev])
            self._name_nodes[instr.dest] = nid
            self._prev = nid

        # ── ASSIGN ───────────────────────────────────────────────────────────
        elif op is IROpcode.ASSIGN:
            src_nid = self._get_src(instr.src1)
            self._set_tmp(instr.dest, src_nid)  # alias

        # ── Binary ops ───────────────────────────────────────────────────────
        elif op in _BINARY_OPS:
            s1 = self._get_src(instr.src1)
            s2 = self._get_src(instr.src2)
            nid = self._node_id(op.value)
            node = DAGNode(node_id=nid, kind=NodeKind.OP, op=op.value,
                           dt=self._current_dt, deps=[s1, s2])
            self._add(node, deps=[s1, s2])
            self._set_tmp(instr.dest, nid)

        # ── Unary ops ─────────────────────────────────────────────────────────
        elif op in _UNARY_OPS:
            s1  = self._get_src(instr.src1)
            nid = self._node_id(op.value)
            node = DAGNode(node_id=nid, kind=NodeKind.OP, op=op.value,
                           dt=self._current_dt, deps=[s1])
            self._add(node, deps=[s1])
            self._set_tmp(instr.dest, nid)

        # ── CALL ─────────────────────────────────────────────────────────────
        elif op is IROpcode.CALL:
            func_nid = self._get_src(instr.src1)
            arg_nids = []
            for a in instr.meta.get("args", []):
                if isinstance(a, tuple):
                    arg_nids.append(self._get_src(a[1]))
                else:
                    arg_nids.append(self._get_src(a))
            nid  = self._node_id("call")
            deps = [func_nid, self._prev] + arg_nids
            node = DAGNode(node_id=nid, kind=NodeKind.OP, op="CALL",
                           dt=self._current_dt, deps=deps,
                           meta={"n_args": len(arg_nids)})
            self._add(node, deps=deps)
            self._set_tmp(instr.dest, nid)
            self._prev = nid

        # ── RETURN ───────────────────────────────────────────────────────────
        elif op is IROpcode.RETURN:
            val_nid = self._get_src(instr.src1) if instr.src1 else self._prev
            nid     = self._node_id("return")
            node    = DAGNode(node_id=nid, kind=NodeKind.CTRL, op="RETURN",
                              dt=self._DT_CTRL, deps=[val_nid, self._prev])
            self._add(node, deps=[val_nid, self._prev])
            self._prev = nid

        # ── JUMP ─────────────────────────────────────────────────────────────
        elif op is IROpcode.JUMP:
            nid  = self._node_id("jmp")
            node = DAGNode(node_id=nid, kind=NodeKind.CTRL, op="JUMP",
                           dt=self._DT_CTRL, deps=[self._prev],
                           meta={"target": instr.meta.get("target")})
            self._add(node, deps=[self._prev])
            self._prev = nid

        # ── CJUMP ────────────────────────────────────────────────────────────
        elif op is IROpcode.CJUMP:
            cond_nid = self._get_src(instr.src1)
            nid      = self._node_id("cjmp")
            node     = DAGNode(node_id=nid, kind=NodeKind.CTRL, op="CJUMP",
                               dt=self._DT_CTRL, deps=[cond_nid, self._prev],
                               meta={"true":  instr.meta.get("true"),
                                     "false": instr.meta.get("false")})
            self._add(node, deps=[cond_nid, self._prev])
            self._prev = nid

        # ── RAISE ────────────────────────────────────────────────────────────
        elif op is IROpcode.RAISE:
            exc_nid = self._get_src(instr.src1) if instr.src1 else self._prev
            nid     = self._node_id("raise")
            node    = DAGNode(node_id=nid, kind=NodeKind.CTRL, op="RAISE",
                              dt=self._DT_CTRL, deps=[exc_nid, self._prev])
            self._add(node, deps=[exc_nid, self._prev])
            self._prev = nid

        # ── LOAD_ATTR ────────────────────────────────────────────────────────
        elif op is IROpcode.LOAD_ATTR:
            obj_nid = self._get_src(instr.src1)
            nid     = self._node_id(f"getattr_{instr.meta.get('attr','')}")
            node    = DAGNode(node_id=nid, kind=NodeKind.OP, op="LOAD_ATTR",
                              dt=self._current_dt, deps=[obj_nid],
                              meta={"attr": instr.meta.get("attr")})
            self._add(node, deps=[obj_nid])
            self._set_tmp(instr.dest, nid)

        # ── STORE_ATTR ───────────────────────────────────────────────────────
        elif op is IROpcode.STORE_ATTR:
            obj_nid = self._get_src(instr.src1)
            val_nid = self._get_src(instr.src2)
            nid     = self._node_id(f"setattr_{instr.meta.get('attr','')}")
            node    = DAGNode(node_id=nid, kind=NodeKind.OP, op="STORE_ATTR",
                              dt=self._current_dt, deps=[obj_nid, val_nid, self._prev],
                              meta={"attr": instr.meta.get("attr")})
            self._add(node, deps=[obj_nid, val_nid, self._prev])
            self._prev = nid

        # ── LOAD_INDEX / STORE_INDEX ─────────────────────────────────────────
        elif op is IROpcode.LOAD_INDEX:
            obj_nid = self._get_src(instr.src1)
            idx_nid = self._get_src(instr.src2)
            nid     = self._node_id("getitem")
            node    = DAGNode(node_id=nid, kind=NodeKind.OP, op="LOAD_INDEX",
                              dt=self._current_dt, deps=[obj_nid, idx_nid])
            self._add(node, deps=[obj_nid, idx_nid])
            self._set_tmp(instr.dest, nid)

        elif op is IROpcode.STORE_INDEX:
            obj_nid = self._get_src(instr.src1)
            idx_nid = self._get_src(instr.src2)
            val_nid = self._get_src(instr.meta.get("value"))
            nid     = self._node_id("setitem")
            node    = DAGNode(node_id=nid, kind=NodeKind.OP, op="STORE_INDEX",
                              dt=self._current_dt,
                              deps=[obj_nid, idx_nid, val_nid, self._prev])
            self._add(node, deps=[obj_nid, idx_nid, val_nid, self._prev])
            self._prev = nid

        # ── BUILD_* ───────────────────────────────────────────────────────────
        elif op in _BUILD_OPS:
            items   = instr.meta.get("items", [])
            dep_nids = [self._get_src(i) for i in items]
            nid     = self._node_id(op.value)
            node    = DAGNode(node_id=nid, kind=NodeKind.OP, op=op.value,
                              dt=self._current_dt, deps=dep_nids,
                              meta={"n": len(items)})
            self._add(node, deps=dep_nids)
            self._set_tmp(instr.dest, nid)

        # ── GET_ITER / FOR_ITER ───────────────────────────────────────────────
        elif op is IROpcode.GET_ITER:
            src_nid = self._get_src(instr.src1)
            nid     = self._node_id("get_iter")
            node    = DAGNode(node_id=nid, kind=NodeKind.OP, op="GET_ITER",
                              dt=self._current_dt, deps=[src_nid])
            self._add(node, deps=[src_nid])
            self._set_tmp(instr.dest, nid)

        elif op is IROpcode.FOR_ITER:
            iter_nid = self._get_src(instr.src1)
            nid      = self._node_id("for_iter")
            node     = DAGNode(node_id=nid, kind=NodeKind.CTRL, op="FOR_ITER",
                               dt=self._DT_CTRL, deps=[iter_nid, self._prev],
                               meta={"end": instr.meta.get("end")})
            self._add(node, deps=[iter_nid, self._prev])
            self._set_tmp(instr.dest, nid)
            self._prev = nid

        # ── SETUP_EXCEPT / END_EXCEPT / POP/PUSH EXCEPT ───────────────────────
        elif op in (IROpcode.SETUP_EXCEPT, IROpcode.END_EXCEPT,
                    IROpcode.POP_EXCEPT, IROpcode.PUSH_EXCEPT):
            nid  = self._node_id(op.value)
            node = DAGNode(node_id=nid, kind=NodeKind.CTRL, op=op.value,
                           dt=self._DT_CTRL, deps=[self._prev],
                           meta=dict(instr.meta))
            self._add(node, deps=[self._prev])
            if instr.dest:
                self._set_tmp(instr.dest, nid)
            self._prev = nid

        # ── IMPORT ───────────────────────────────────────────────────────────
        elif op in (IROpcode.IMPORT_NAME, IROpcode.IMPORT_FROM,
                    IROpcode.IMPORT_STAR):
            nid  = self._node_id(op.value)
            deps = [self._prev]
            if instr.src1:
                deps.append(self._get_src(instr.src1))
            node = DAGNode(node_id=nid, kind=NodeKind.OP, op=op.value,
                           dt=self._current_dt, deps=deps,
                           meta=dict(instr.meta))
            self._add(node, deps=deps)
            self._set_tmp(instr.dest, nid)

        # ── MAKE_FUNCTION / MAKE_CLASS ────────────────────────────────────────
        elif op in (IROpcode.MAKE_FUNCTION, IROpcode.MAKE_CLASS):
            nid  = self._node_id(op.value + f"_{instr.meta.get('name','')}")
            node = DAGNode(node_id=nid, kind=NodeKind.OP, op=op.value,
                           dt=self._current_dt, deps=[self._prev],
                           meta={"name": instr.meta.get("name")})
            self._add(node, deps=[self._prev])
            self._set_tmp(instr.dest, nid)

        # ── YIELD ────────────────────────────────────────────────────────────
        elif op is IROpcode.YIELD:
            val_nid = self._get_src(instr.src1) if instr.src1 else self._prev
            nid     = self._node_id("yield")
            node    = DAGNode(node_id=nid, kind=NodeKind.CTRL, op="YIELD",
                              dt=self._DT_CTRL, deps=[val_nid, self._prev])
            self._add(node, deps=[val_nid, self._prev])
            self._set_tmp(instr.dest, nid)
            self._prev = nid

        # ── NOP / GLOBAL_DECL / NONLOCAL_DECL / DELETE_NAME ──────────────────
        elif op in (IROpcode.NOP, IROpcode.GLOBAL_DECL,
                    IROpcode.NONLOCAL_DECL, IROpcode.DELETE_NAME):
            nid  = self._node_id(op.value)
            node = DAGNode(node_id=nid, kind=NodeKind.CTRL, op=op.value,
                           dt=self._DT_MERGE, deps=[self._prev])
            self._add(node, deps=[self._prev])

        # ── UNPACK_SEQ ───────────────────────────────────────────────────────
        elif op is IROpcode.UNPACK_SEQ:
            src_nid = self._get_src(instr.src1)
            nid     = self._node_id("unpack")
            targets = instr.meta.get("targets", [])
            node    = DAGNode(node_id=nid, kind=NodeKind.OP, op="UNPACK_SEQ",
                              dt=self._current_dt, deps=[src_nid],
                              meta={"targets": targets, "n": len(targets)})
            self._add(node, deps=[src_nid])
            # each target gets its own sub-node
            for i, tgt in enumerate(targets):
                sub_nid  = self._node_id(f"unpack_{i}_{tgt}")
                sub_node = DAGNode(node_id=sub_nid, kind=NodeKind.OP,
                                   op="UNPACK_ELEM", dt=self._current_dt + i * 0.01,
                                   deps=[nid], meta={"index": i, "target": tgt})
                self._dag.add_node(sub_node)
                self._dag.add_edge(DAGEdge(src=nid, dst=sub_nid,
                                           op="UNPACK_ELEM", dt=0.01))
                self._name_nodes[tgt] = sub_nid

        else:
            # Generic fallback
            nid  = self._node_id(op.value)
            deps = [self._prev]
            if instr.src1: deps.append(self._get_src(instr.src1))
            if instr.src2: deps.append(self._get_src(instr.src2))
            node = DAGNode(node_id=nid, kind=NodeKind.OP, op=op.value,
                           dt=self._current_dt, deps=deps)
            self._add(node, deps=deps)
            self._set_tmp(instr.dest, nid)

    # ── internal helpers ──────────────────────────────────────────────────────

    def _node_id(self, hint: str = "") -> str:
        self._counter += 1
        h = hashlib.sha1(f"{self._counter}:{hint}".encode()).hexdigest()[:8]
        return f"N{self._counter:05d}_{h}"

    def _add(self, node: DAGNode, deps: List[Optional[str]]):
        self._dag.add_node(node)
        for dep in deps:
            if dep and dep != node.node_id:
                self._dag.add_edge(DAGEdge(
                    src=dep, dst=node.node_id,
                    op=node.op, dt=node.dt,
                ))

    def _set_tmp(self, var: Optional[str], nid: str):
        if var:
            self._tmp_nodes[var] = nid

    def _get_src(self, var: Optional[str]) -> str:
        if var is None:
            return self._prev
        nid = self._tmp_nodes.get(var) or self._name_nodes.get(var)
        if nid:
            return nid
        # Create a lazy NAME node on first reference
        lazy_id = self._node_id(f"lazy_{var}")
        node    = DAGNode(node_id=lazy_id, kind=NodeKind.NAME, op="LOAD_NAME",
                          name=var, dt=self._current_dt)
        self._dag.add_node(node)
        self._tmp_nodes[var] = lazy_id
        return lazy_id

    def _topo_sort(self, dag: ExecutionDAG) -> List[str]:
        """Kahn's algorithm for topological sort."""
        in_deg = {nid: 0 for nid in dag.nodes}
        succ   = {nid: [] for nid in dag.nodes}
        for e in dag.edges:
            if e.src in dag.nodes and e.dst in dag.nodes:
                succ[e.src].append(e.dst)
                in_deg[e.dst] += 1

        queue  = [nid for nid, d in in_deg.items() if d == 0]
        order  = []
        while queue:
            nid = queue.pop(0)
            order.append(nid)
            for s in succ[nid]:
                in_deg[s] -= 1
                if in_deg[s] == 0:
                    queue.append(s)
        # append any remaining (cycles from junk)
        for nid in dag.nodes:
            if nid not in order:
                order.append(nid)
        return order


# ─── operator sets ────────────────────────────────────────────────────────────

_BINARY_OPS = frozenset({
    IROpcode.ADD, IROpcode.SUB, IROpcode.MUL, IROpcode.DIV,
    IROpcode.FLOOR_DIV, IROpcode.MOD, IROpcode.POW, IROpcode.MATMUL,
    IROpcode.BAND, IROpcode.BOR, IROpcode.BXOR,
    IROpcode.LSHIFT, IROpcode.RSHIFT,
    IROpcode.AND, IROpcode.OR,
    IROpcode.EQ, IROpcode.NE, IROpcode.LT, IROpcode.LE,
    IROpcode.GT, IROpcode.GE,
    IROpcode.IS, IROpcode.IS_NOT, IROpcode.IN, IROpcode.NOT_IN,
})

_UNARY_OPS = frozenset({
    IROpcode.NEG, IROpcode.POS, IROpcode.BNOT, IROpcode.NOT,
})

_BUILD_OPS = frozenset({
    IROpcode.BUILD_LIST, IROpcode.BUILD_TUPLE,
    IROpcode.BUILD_DICT, IROpcode.BUILD_SET,
})


# ─── convenience ─────────────────────────────────────────────────────────────

def build_dags(module: IRModule) -> Dict[str, ExecutionDAG]:
    return GTVMGraphBuilder().build_all(module)
