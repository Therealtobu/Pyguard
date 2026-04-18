"""
Module 0.4 – Static Profiler
Estimates "hotness" of functions and basic blocks using heuristics:
- Loop depth → higher weight
- Call frequency (estimated from callee count)
- Recursive functions
- Name-based heuristics (__init__, compute_, process_, etc.)
Output: annotates each IRFunction and BasicBlock with a .weight float.
Marks module.hot_functions (candidates for native compilation in stage 4).
"""

from __future__ import annotations
import ast
import re
from collections import defaultdict
from typing import Dict, Set

from common.ir import (
    IROpcode, IRInstruction, BasicBlock, CFG,
    IRFunction, IRClass, IRModule
)

# ─── heuristic constants ─────────────────────────────────────────────────────

HOT_NAME_PATTERNS = [
    r"^compute_", r"^process_", r"^run_", r"^execute_",
    r"^solve_", r"^train_", r"^fit_", r"^predict_",
    r"^encode_", r"^decode_", r"^transform_",
    r"^__call__$", r"^forward$", r"^step$",
]

COLD_NAME_PATTERNS = [
    r"^setup_", r"^teardown_", r"^cleanup_",
    r"^__repr__$", r"^__str__$", r"^__doc__",
    r"^test_", r"^debug_",
]

LOOP_WEIGHT        = 5.0   # multiplier per loop nesting level
RECURSION_BONUS    = 3.0
HOT_NAME_BONUS     = 2.0
COLD_NAME_PENALTY  = 0.3
BASE_WEIGHT        = 1.0
HOT_THRESHOLD      = 4.0   # weight >= this → candidate for native


class StaticProfiler:

    def run(self, module: IRModule) -> ProfilerReport:
        report = ProfilerReport()

        all_fns = self._collect_functions(module)

        # 1. compute call graph
        call_graph = self._build_call_graph(all_fns)

        # 2. detect recursive functions
        recursive = self._find_recursive(call_graph)

        # 3. score each function
        for fname, fn in all_fns.items():
            weight = self._score_function(fname, fn, call_graph, recursive)
            fn.constants["__profile_weight__"] = weight
            report.weights[fname] = weight

            if weight >= HOT_THRESHOLD:
                report.hot_functions.append(fname)

            # 4. annotate CFG blocks
            if fn.cfg:
                self._annotate_blocks(fn.cfg, fn)

        module.hot_functions = report.hot_functions
        return report

    # ── function scoring ──────────────────────────────────────────────────────

    def _score_function(
        self,
        fname: str,
        fn: IRFunction,
        call_graph: Dict[str, Set[str]],
        recursive: Set[str],
    ) -> float:
        weight = BASE_WEIGHT

        # Name heuristics
        short = fname.split(".")[-1]
        for pat in HOT_NAME_PATTERNS:
            if re.match(pat, short):
                weight += HOT_NAME_BONUS
                break
        for pat in COLD_NAME_PATTERNS:
            if re.match(pat, short):
                weight *= COLD_NAME_PENALTY
                break

        # Recursion
        if fname in recursive:
            weight += RECURSION_BONUS

        # Loop depth (from AST)
        ast_node = fn.constants.get("__ast_node__")
        if ast_node:
            max_depth = self._max_loop_depth(ast_node)
            weight += max_depth * LOOP_WEIGHT

        # Called frequently (in-degree in call graph)
        in_degree = sum(1 for callers in call_graph.values() if fname in callers)
        weight += min(in_degree, 5) * 0.5

        # Number of instructions
        if fn.cfg:
            n_instrs = sum(len(b.instructions) for b in fn.cfg.blocks.values())
        else:
            n_instrs = len(fn.instructions)
        weight += min(n_instrs / 50, 3.0)  # up to +3 for large functions

        # Generator penalty (hard to compile to native)
        if fn.is_generator:
            weight *= 0.5

        return round(weight, 2)

    def _max_loop_depth(self, node: ast.AST, depth: int = 0) -> int:
        """Recursively find the maximum loop nesting depth."""
        if isinstance(node, (ast.For, ast.While)):
            depth += 1
        max_d = depth
        for child in ast.iter_child_nodes(node):
            max_d = max(max_d, self._max_loop_depth(child, depth))
        return max_d

    # ── call graph ────────────────────────────────────────────────────────────

    def _build_call_graph(
        self, all_fns: Dict[str, IRFunction]
    ) -> Dict[str, Set[str]]:
        """
        call_graph[caller] = set of callee names (best-effort static analysis).
        """
        cg: Dict[str, Set[str]] = defaultdict(set)
        known_names = set(all_fns.keys()) | {n.split(".")[-1] for n in all_fns}

        for fname, fn in all_fns.items():
            ast_node = fn.constants.get("__ast_node__")
            if not ast_node:
                continue
            for node in ast.walk(ast_node):
                if isinstance(node, ast.Call):
                    callee = self._resolve_callee(node)
                    if callee and callee in known_names:
                        cg[fname].add(callee)

        return cg

    def _resolve_callee(self, call: ast.Call) -> str | None:
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return None

    def _find_recursive(self, cg: Dict[str, Set[str]]) -> Set[str]:
        """DFS to detect direct or indirect recursion."""
        recursive: Set[str] = set()

        def dfs(fn: str, path: list[str]) -> bool:
            if fn in path:
                recursive.update(path[path.index(fn):])
                return True
            for callee in cg.get(fn, set()):
                if dfs(callee, path + [fn]):
                    return True
            return False

        for fn in cg:
            dfs(fn, [])

        return recursive

    # ── block annotation ──────────────────────────────────────────────────────

    def _annotate_blocks(self, cfg: CFG, fn: IRFunction):
        """
        Estimate each block's weight:
        - Blocks inside loops get higher weight
        - Loop header / back-edge targets are hottest
        """
        fn_weight = fn.constants.get("__profile_weight__", BASE_WEIGHT)
        back_edges = self._find_back_edges(cfg)

        # BFS to assign loop depth
        depth: Dict[str, int] = defaultdict(int)
        for (src, dst) in back_edges:
            # All blocks reachable from dst and from which src is reachable
            # are in the loop body – increment their depth
            loop_body = self._loop_body(cfg, dst, src)
            for lbl in loop_body:
                depth[lbl] += 1

        for lbl, blk in cfg.blocks.items():
            d = depth[lbl]
            blk.weight = fn_weight * (1.0 + d * LOOP_WEIGHT * 0.2)

    def _find_back_edges(self, cfg: CFG) -> list[tuple[str, str]]:
        """DFS-based back edge detection (src → dst where dst is ancestor)."""
        visited:   Set[str] = set()
        in_stack:  Set[str] = set()
        back_edges = []

        def dfs(lbl: str):
            visited.add(lbl)
            in_stack.add(lbl)
            for s in cfg.blocks.get(lbl, BasicBlock(label=lbl)).successors:
                if s not in visited:
                    dfs(s)
                elif s in in_stack:
                    back_edges.append((lbl, s))
            in_stack.discard(lbl)

        if cfg.entry:
            dfs(cfg.entry)
        return back_edges

    def _loop_body(self, cfg: CFG, header: str, tail: str) -> Set[str]:
        """All blocks in the natural loop from header to tail."""
        body:    Set[str] = {header}
        worklist = [tail]
        while worklist:
            lbl = worklist.pop()
            if lbl not in body:
                body.add(lbl)
                for pred in cfg.blocks.get(lbl, BasicBlock(label=lbl)).predecessors:
                    worklist.append(pred)
        return body

    # ── helpers ───────────────────────────────────────────────────────────────

    def _collect_functions(self, module: IRModule) -> Dict[str, IRFunction]:
        result = dict(module.functions)
        for cls in module.classes.values():
            for mname, method in cls.methods.items():
                result[f"{cls.name}.{mname}"] = method
        return result


# ─── report ──────────────────────────────────────────────────────────────────

class ProfilerReport:
    def __init__(self):
        self.weights:       Dict[str, float] = {}
        self.hot_functions: list[str]        = []

    def summary(self) -> str:
        lines = ["  Profile weights (top 10):"]
        top = sorted(self.weights.items(), key=lambda x: -x[1])[:10]
        for name, w in top:
            hot = " ← HOT" if name in self.hot_functions else ""
            lines.append(f"    {name:<40} {w:5.2f}{hot}")
        return "\n".join(lines)


# ─── convenience ─────────────────────────────────────────────────────────────

def profile(module: IRModule) -> ProfilerReport:
    return StaticProfiler().run(module)
