"""
Module 0.3 – Data Dependency Analysis
Computes use-def chains, live variable sets, and data-flow facts
for each function's CFG. Results are stored back onto BasicBlocks.
"""

from __future__ import annotations
from collections import defaultdict
from typing import Set, Dict, List, Optional

from common.ir import (
    IROpcode, IRInstruction, BasicBlock, CFG,
    IRFunction, IRClass, IRModule
)


# ─── Use/Def extraction ───────────────────────────────────────────────────────

def _defs(instr: IRInstruction) -> Set[str]:
    """Variables written by this instruction."""
    d: Set[str] = set()
    if instr.dest:
        d.add(instr.dest)
    if instr.op is IROpcode.UNPACK_SEQ:
        d.update(t for t in instr.meta.get("targets", []) if isinstance(t, str))
    return d


def _uses(instr: IRInstruction) -> Set[str]:
    """Variables read by this instruction (non-temp names only)."""
    u: Set[str] = set()
    for var in (instr.src1, instr.src2):
        if var and not var.startswith("$"):
            u.add(var)
    # args in meta
    for arg in instr.meta.get("args", []):
        if isinstance(arg, str) and not arg.startswith("$"):
            u.add(arg)
    for v in instr.meta.get("kwargs", {}).values():
        if isinstance(v, str) and not v.startswith("$"):
            u.add(v)
    for v in instr.meta.get("items", []):
        if isinstance(v, str) and not v.startswith("$"):
            u.add(v)
    for v in instr.meta.get("keys", []):
        if isinstance(v, str) and not v.startswith("$"):
            u.add(v)
    for v in instr.meta.get("values", []):
        if isinstance(v, str) and not v.startswith("$"):
            u.add(v)
    return u


# ─── Block-level gen/kill ─────────────────────────────────────────────────────

def _compute_gen_kill(
    block: BasicBlock,
) -> tuple[Set[str], Set[str]]:
    """
    gen  = vars used before being defined in this block
    kill = vars defined in this block
    """
    gen:  Set[str] = set()
    kill: Set[str] = set()
    for instr in block.instructions:
        uses = _uses(instr)
        defs = _defs(instr)
        gen  |= uses - kill   # used before killed
        kill |= defs
    return gen, kill


# ─── Liveness analysis ────────────────────────────────────────────────────────

class LivenessAnalysis:
    """
    Standard backward dataflow liveness analysis.
    live_in[B]  = gen[B] ∪ (live_out[B] − kill[B])
    live_out[B] = ∪ live_in[S] for S in successors(B)
    """

    def __init__(self, cfg: CFG):
        self.cfg      = cfg
        self.live_in:  Dict[str, Set[str]] = defaultdict(set)
        self.live_out: Dict[str, Set[str]] = defaultdict(set)
        self._gen:     Dict[str, Set[str]] = {}
        self._kill:    Dict[str, Set[str]] = {}

    def run(self):
        for lbl, blk in self.cfg.blocks.items():
            self._gen[lbl], self._kill[lbl] = _compute_gen_kill(blk)

        changed = True
        while changed:
            changed = False
            for lbl in reversed(list(self.cfg.blocks)):
                blk = self.cfg.blocks[lbl]
                # live_out = union of successors' live_in
                new_out: Set[str] = set()
                for s in blk.successors:
                    new_out |= self.live_in.get(s, set())
                # live_in = gen ∪ (live_out − kill)
                new_in = self._gen[lbl] | (new_out - self._kill[lbl])
                if new_in != self.live_in[lbl] or new_out != self.live_out[lbl]:
                    self.live_in[lbl]  = new_in
                    self.live_out[lbl] = new_out
                    changed = True


# ─── Use-Def chains ───────────────────────────────────────────────────────────

class UseDefChains:
    """
    Maps each use of a variable (block_label, instr_index) to the
    set of definitions (block_label, instr_index) that can reach it.
    """

    def __init__(self, cfg: CFG):
        self.cfg = cfg
        # reaching_defs[block][var] = set of (block, idx) that defined var
        self.reaching: Dict[str, Dict[str, Set[tuple]]] = defaultdict(lambda: defaultdict(set))
        self.use_to_defs: Dict[tuple, Set[tuple]] = defaultdict(set)
        self.def_to_uses: Dict[tuple, Set[tuple]] = defaultdict(set)

    def run(self):
        """Forward dataflow: reaching definitions."""
        # init OUT for each block
        out: Dict[str, Dict[str, Set[tuple]]] = defaultdict(lambda: defaultdict(set))
        changed = True
        while changed:
            changed = False
            for lbl, blk in self.cfg.blocks.items():
                # IN = merge of predecessors' OUT
                in_: Dict[str, Set[tuple]] = defaultdict(set)
                for pred in blk.predecessors:
                    for var, defs in out[pred].items():
                        in_[var] |= defs

                # propagate through block
                cur = {v: set(s) for v, s in in_.items()}
                for idx, instr in enumerate(blk.instructions):
                    for var in _defs(instr):
                        cur[var] = {(lbl, idx)}  # kill old, gen new

                new_out = cur
                if new_out != out[lbl]:
                    out[lbl] = new_out
                    changed  = True

        # Build use→def and def→use
        for lbl, blk in self.cfg.blocks.items():
            # reconstruct per-instruction reaching defs (one pass)
            in_: Dict[str, Set[tuple]] = defaultdict(set)
            for pred in blk.predecessors:
                for var, defs in out[pred].items():
                    in_[var] |= defs
            cur = {v: set(s) for v, s in in_.items()}
            for idx, instr in enumerate(blk.instructions):
                use_pt = (lbl, idx)
                for var in _uses(instr):
                    for def_pt in cur.get(var, set()):
                        self.use_to_defs[use_pt].add(def_pt)
                        self.def_to_uses[def_pt].add(use_pt)
                for var in _defs(instr):
                    cur[var] = {(lbl, idx)}


# ─── Variable flow summary ────────────────────────────────────────────────────

class VariableFlowSummary:
    """
    High-level summary of variable usage in a function:
    - Which variables are only-read (never assigned locally)
    - Which are only-written (never read)
    - Which are loop-carried (defined in loop, used in later iteration)
    - Estimated "hotness" of each variable (use count)
    """

    def __init__(self):
        self.read_only:     Set[str] = set()
        self.write_only:    Set[str] = set()
        self.loop_carried:  Set[str] = set()
        self.use_count:     Dict[str, int] = defaultdict(int)
        self.def_count:     Dict[str, int] = defaultdict(int)

    def compute(self, cfg: CFG) -> None:
        all_uses: Set[str] = set()
        all_defs: Set[str] = set()

        for blk in cfg.blocks.values():
            for instr in blk.instructions:
                for v in _uses(instr):
                    all_uses.add(v)
                    self.use_count[v] += 1
                for v in _defs(instr):
                    all_defs.add(v)
                    self.def_count[v] += 1

        self.read_only  = all_uses  - all_defs
        self.write_only = all_defs  - all_uses

        # Loop-carried: defined in a block that has a back-edge predecessor
        # (simplified: in a block whose successors include a predecessor)
        back_edge_defs: Set[str] = set()
        for lbl, blk in cfg.blocks.items():
            # detect back edges: successor is a predecessor of current block
            for s in blk.successors:
                if s in blk.predecessors or s == lbl:
                    for instr in blk.instructions:
                        back_edge_defs |= _defs(instr)
        self.loop_carried = back_edge_defs & all_uses


# ─── Main analysis class ──────────────────────────────────────────────────────

class DataDependencyAnalysis:
    """
    Runs liveness + use-def + variable flow on all functions in a module.
    Attaches results to each BasicBlock and IRFunction.
    """

    def run(self, module: IRModule) -> AnalysisResults:
        results = AnalysisResults()

        all_fns: Dict[str, IRFunction] = {}
        for name, fn in module.functions.items():
            all_fns[name] = fn
        for cls in module.classes.values():
            for mname, method in cls.methods.items():
                all_fns[f"{cls.name}.{mname}"] = method

        for fname, fn in all_fns.items():
            if fn.cfg is None:
                continue

            # Liveness
            liveness = LivenessAnalysis(fn.cfg)
            liveness.run()

            # Attach live_in / live_out to each block
            for lbl, blk in fn.cfg.blocks.items():
                blk.instructions  # already exists
                # store annotations in a side dict (blocks don't have these fields natively)
                results.live_in [fname][lbl] = liveness.live_in [lbl]
                results.live_out[fname][lbl] = liveness.live_out[lbl]

            # Use-def chains
            ud = UseDefChains(fn.cfg)
            ud.run()
            results.use_def[fname] = ud

            # Variable flow
            vf = VariableFlowSummary()
            vf.compute(fn.cfg)
            results.var_flow[fname] = vf

            # Store on function for later stages
            fn.constants["__liveness__"] = liveness
            fn.constants["__use_def__"]  = ud
            fn.constants["__var_flow__"] = vf

        return results


class AnalysisResults:
    def __init__(self):
        self.live_in:  Dict[str, Dict[str, Set[str]]] = defaultdict(dict)
        self.live_out: Dict[str, Dict[str, Set[str]]] = defaultdict(dict)
        self.use_def:  Dict[str, UseDefChains]         = {}
        self.var_flow: Dict[str, VariableFlowSummary]  = {}

    def summary(self) -> str:
        lines = []
        for fname, vf in self.var_flow.items():
            lines.append(f"  {fname}:")
            lines.append(f"    read-only:    {sorted(vf.read_only)[:8]}")
            lines.append(f"    write-only:   {sorted(vf.write_only)[:8]}")
            lines.append(f"    loop-carried: {sorted(vf.loop_carried)[:8]}")
            top_used = sorted(vf.use_count, key=lambda k: -vf.use_count[k])[:5]
            lines.append(f"    top used vars: {top_used}")
        return "\n".join(lines)


# ─── convenience ─────────────────────────────────────────────────────────────

def analyze(module: IRModule) -> AnalysisResults:
    return DataDependencyAnalysis().run(module)
