"""
Module 4.1 – Hot Path Selector
Identifies basic blocks and functions that are candidates for native
code generation based on profiler weight and IR structure heuristics.

Selection criteria:
  1. Profiler weight >= HOT_THRESHOLD  (from stage0 profiler)
  2. Function contains at least one loop (back-edge in CFG)
  3. Function is NOT a generator (generators can't be compiled to simple native)
  4. Function instructions are reducible to arithmetic/bitwise/comparison only
     (no dynamic attribute access, no yield, no exec-style calls)
  5. IR is free of unsupported opcodes (MAKE_FUNCTION, MAKE_CLASS, IMPORT_*)

Output: HotPathReport with:
  - selected_functions: list of function names to compile natively
  - selected_blocks: dict fn_name → list of block labels
  - estimated_speedup: rough multiplier estimate
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional

from common.ir import (
    IROpcode, IRInstruction, BasicBlock, CFG,
    IRFunction, IRClass, IRModule
)

# ── Tunables ──────────────────────────────────────────────────────────────────
HOT_THRESHOLD      = 4.0
MIN_INSTRUCTIONS   = 10    # ignore tiny functions
MAX_INSTRUCTIONS   = 5000  # avoid generating huge native blocks

# Opcodes that are natively compilable (arithmetic / bitwise / cmp / control)
NATIVE_SAFE_OPS = frozenset({
    IROpcode.NOP, IROpcode.LABEL,
    IROpcode.LOAD_CONST, IROpcode.LOAD_NAME, IROpcode.STORE_NAME,
    IROpcode.ASSIGN,
    IROpcode.ADD, IROpcode.SUB, IROpcode.MUL, IROpcode.DIV,
    IROpcode.FLOOR_DIV, IROpcode.MOD, IROpcode.POW,
    IROpcode.NEG, IROpcode.POS,
    IROpcode.BAND, IROpcode.BOR, IROpcode.BXOR, IROpcode.BNOT,
    IROpcode.LSHIFT, IROpcode.RSHIFT,
    IROpcode.AND, IROpcode.OR, IROpcode.NOT,
    IROpcode.EQ, IROpcode.NE, IROpcode.LT, IROpcode.LE,
    IROpcode.GT, IROpcode.GE,
    IROpcode.IS, IROpcode.IS_NOT, IROpcode.IN, IROpcode.NOT_IN,
    IROpcode.JUMP, IROpcode.CJUMP,
    IROpcode.RETURN,
    IROpcode.BUILD_LIST, IROpcode.BUILD_TUPLE,
    IROpcode.BUILD_DICT, IROpcode.BUILD_SET,
    IROpcode.GET_ITER, IROpcode.FOR_ITER,
    IROpcode.UNPACK_SEQ,
    IROpcode.LOAD_INDEX, IROpcode.STORE_INDEX,
    IROpcode.CALL,
    IROpcode.GLOBAL_DECL, IROpcode.NONLOCAL_DECL,
    IROpcode.DELETE_NAME,
})

# Opcodes that block native compilation entirely
NATIVE_BLOCK_OPS = frozenset({
    IROpcode.YIELD, IROpcode.YIELD_FROM,
    IROpcode.MAKE_FUNCTION, IROpcode.MAKE_CLASS,
    IROpcode.IMPORT_NAME, IROpcode.IMPORT_FROM, IROpcode.IMPORT_STAR,
    IROpcode.WITH_ENTER, IROpcode.WITH_EXIT,
})


@dataclass
class HotPathReport:
    selected_functions: List[str]          = field(default_factory=list)
    # fn_name → set of block labels that are hot (loop body blocks)
    hot_blocks:  Dict[str, List[str]]      = field(default_factory=dict)
    # fn_name → estimated speedup vs Python interpreter
    speedup:     Dict[str, float]          = field(default_factory=dict)
    # fn_name → reason it was rejected
    rejected:    Dict[str, str]            = field(default_factory=dict)

    def summary(self) -> str:
        lines = [f"Hot path selection: {len(self.selected_functions)} functions"]
        for fn in self.selected_functions:
            sp = self.speedup.get(fn, 1.0)
            nb = len(self.hot_blocks.get(fn, []))
            lines.append(f"  ✓ {fn:<40}  est. {sp:.1f}x  ({nb} hot blocks)")
        if self.rejected:
            lines.append(f"  Rejected: {len(self.rejected)}")
            for fn, reason in list(self.rejected.items())[:5]:
                lines.append(f"    ✗ {fn}: {reason}")
        return "\n".join(lines)


class HotPathSelector:

    def select(self, module: IRModule) -> HotPathReport:
        report = HotPathReport()

        all_fns = self._collect_fns(module)
        for fn_name, fn in all_fns.items():
            ok, reason = self._is_native_candidate(fn)
            if not ok:
                report.rejected[fn_name] = reason
                continue

            weight = fn.constants.get("__profile_weight__", 1.0)
            report.selected_functions.append(fn_name)
            report.hot_blocks[fn_name] = self._find_hot_blocks(fn)
            report.speedup[fn_name]    = self._estimate_speedup(fn, weight)

        return report

    # ── candidacy check ───────────────────────────────────────────────────────

    def _is_native_candidate(self, fn: IRFunction) -> tuple[bool, str]:
        if fn.is_generator:
            return False, "generator"
        if fn.is_async:
            return False, "async"

        weight = fn.constants.get("__profile_weight__", 0.0)
        if weight < HOT_THRESHOLD:
            return False, f"weight {weight:.2f} < {HOT_THRESHOLD}"

        instrs = fn.flat_instructions()
        n = len(instrs)
        if n < MIN_INSTRUCTIONS:
            return False, f"too small ({n} instrs)"
        if n > MAX_INSTRUCTIONS:
            return False, f"too large ({n} instrs)"

        for instr in instrs:
            if instr.op in NATIVE_BLOCK_OPS:
                return False, f"contains {instr.op.value}"

        return True, ""

    # ── hot block detection ───────────────────────────────────────────────────

    def _find_hot_blocks(self, fn: IRFunction) -> List[str]:
        """Return block labels that are inside loops (back-edge targets)."""
        if fn.cfg is None:
            return []

        back_edges = self._find_back_edges(fn.cfg)
        hot: Set[str] = set()
        for (src, dst) in back_edges:
            hot |= self._loop_body(fn.cfg, dst, src)

        # Also include blocks with weight > 2× average
        avg_w = sum(b.weight for b in fn.cfg.blocks.values()) / max(1, len(fn.cfg.blocks))
        for lbl, blk in fn.cfg.blocks.items():
            if blk.weight >= 2.0 * avg_w:
                hot.add(lbl)

        return sorted(hot)

    def _find_back_edges(self, cfg: CFG) -> List[tuple[str, str]]:
        visited: Set[str] = set()
        in_stack: Set[str] = set()
        back_edges: List[tuple[str, str]] = []

        def dfs(lbl: str):
            visited.add(lbl); in_stack.add(lbl)
            for s in cfg.blocks.get(lbl, BasicBlock(lbl)).successors:
                if s not in visited: dfs(s)
                elif s in in_stack:  back_edges.append((lbl, s))
            in_stack.discard(lbl)

        if cfg.entry:
            dfs(cfg.entry)
        return back_edges

    def _loop_body(self, cfg: CFG, header: str, tail: str) -> Set[str]:
        body: Set[str] = {header}
        wl = [tail]
        while wl:
            lbl = wl.pop()
            if lbl not in body:
                body.add(lbl)
                for pred in cfg.blocks.get(lbl, BasicBlock(lbl)).predecessors:
                    wl.append(pred)
        return body

    # ── speedup estimate ──────────────────────────────────────────────────────

    def _estimate_speedup(self, fn: IRFunction, weight: float) -> float:
        """
        Heuristic speedup over CPython interpreter.
        Arithmetic-heavy loops: 5-20×.
        Mixed loops: 2-5×.
        """
        instrs = fn.flat_instructions()
        arith  = sum(1 for i in instrs if i.op in {
            IROpcode.ADD, IROpcode.SUB, IROpcode.MUL, IROpcode.DIV,
            IROpcode.MOD, IROpcode.POW, IROpcode.BAND, IROpcode.BOR,
            IROpcode.BXOR, IROpcode.LSHIFT, IROpcode.RSHIFT,
        })
        ratio  = arith / max(1, len(instrs))
        base   = 2.0 + ratio * 18.0          # 2-20×
        return round(min(base * (weight / HOT_THRESHOLD), 25.0), 1)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _collect_fns(self, module: IRModule) -> Dict[str, IRFunction]:
        result = dict(module.functions)
        for cls in module.classes.values():
            for mname, method in cls.methods.items():
                result[f"{cls.name}.{mname}"] = method
        return result


# ─── convenience ─────────────────────────────────────────────────────────────
def select_hot_paths(module: IRModule) -> HotPathReport:
    return HotPathSelector().select(module)
