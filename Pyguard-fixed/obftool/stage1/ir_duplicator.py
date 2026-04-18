"""
Module 1.3 – IR Duplicator
Clones an IRModule into two independent copies: IR_main and IR_shadow.
Each copy is deep-cloned so mutations in one don't affect the other.

Module 1.4 – IR Mutator
Randomly mutates each IR copy to make them structurally different
while preserving semantics:
  • Instruction reordering (within safe windows)
  • False constant injection (adds dead computations)
  • Opcode equivalence substitution (a+b → -((-a)+(-b)) etc.)
  • Label renaming (prefix-based)
  • Register renaming (tmp variable name mangling)
"""

from __future__ import annotations
import copy
import random
from typing import List, Dict

from common.ir import (
    IROpcode, IRInstruction, BasicBlock, CFG,
    IRFunction, IRClass, IRModule
)


# ─────────────────────────────────────────────────────────────────────────────
# Module 1.3 – IR Duplicator
# ─────────────────────────────────────────────────────────────────────────────

class IRDuplicator:
    """
    Deep-clones an IRModule into two variants: (ir_main, ir_shadow).
    """

    def duplicate(self, module: IRModule) -> tuple[IRModule, IRModule]:
        ir_main   = self._clone(module, suffix="_main")
        ir_shadow = self._clone(module, suffix="_shadow")
        return ir_main, ir_shadow

    def _clone(self, module: IRModule, suffix: str) -> IRModule:
        cloned = IRModule(
            name        = module.name + suffix,
            source_file = module.source_file,
        )
        # Deep copy constants (skip non-serialisable AST objects)
        cloned.constants    = self._safe_copy_constants(module.constants)
        cloned.imports      = list(module.imports)
        cloned.hot_functions = list(module.hot_functions)

        # Clone module-level instructions
        cloned.module_instrs = [i.clone() for i in module.module_instrs]

        # Clone functions
        for name, fn in module.functions.items():
            cloned.functions[name] = self._clone_function(fn)

        # Clone classes
        for name, cls in module.classes.items():
            cloned.classes[name] = self._clone_class(cls)

        return cloned

    def _clone_function(self, fn: IRFunction) -> IRFunction:
        new_fn = IRFunction(
            name         = fn.name,
            args         = list(fn.args),
            varargs      = fn.varargs,
            kwargs       = fn.kwargs,
            defaults     = dict(fn.defaults),
            locals_      = list(fn.locals_),
            globals_used = list(fn.globals_used),
            is_generator = fn.is_generator,
            is_async     = fn.is_async,
            decorators   = list(fn.decorators),
        )
        new_fn.instructions = [i.clone() for i in fn.instructions]
        new_fn.constants     = self._safe_copy_constants(fn.constants)
        for name, nested in fn.nested.items():
            new_fn.nested[name] = self._clone_function(nested)
        if fn.cfg:
            new_fn.cfg = self._clone_cfg(fn.cfg)
        return new_fn

    def _clone_class(self, cls: IRClass) -> IRClass:
        new_cls = IRClass(
            name       = cls.name,
            bases      = list(cls.bases),
            decorators = list(cls.decorators),
        )
        new_cls.attrs = dict(cls.attrs)
        for name, method in cls.methods.items():
            new_cls.methods[name] = self._clone_function(method)
        return new_cls

    def _clone_cfg(self, cfg: CFG) -> CFG:
        new_cfg = CFG(entry=cfg.entry, exit_=cfg.exit_)
        for lbl, blk in cfg.blocks.items():
            new_blk = BasicBlock(
                label        = blk.label,
                predecessors = list(blk.predecessors),
                successors   = list(blk.successors),
                weight       = blk.weight,
            )
            new_blk.instructions = [i.clone() for i in blk.instructions]
            new_cfg.blocks[lbl] = new_blk
        return new_cfg

    def _safe_copy_constants(self, d: Dict) -> Dict:
        """Copy a constants dict, skipping un-deepcopyable AST nodes."""
        out = {}
        for k, v in d.items():
            if k.startswith("__") and k.endswith("__"):
                try:
                    out[k] = copy.deepcopy(v)
                except Exception:
                    out[k] = None   # drop if un-copyable
            else:
                try:
                    out[k] = copy.deepcopy(v)
                except Exception:
                    out[k] = v
        return out


# ─────────────────────────────────────────────────────────────────────────────
# Module 1.4 – IR Mutator
# ─────────────────────────────────────────────────────────────────────────────

# Opcodes safe to reorder (no side effects, result used later)
_REORDERABLE = frozenset({
    IROpcode.LOAD_CONST,
    IROpcode.LOAD_NAME,
    IROpcode.LOAD_ATTR,
    IROpcode.LOAD_INDEX,
    IROpcode.ADD, IROpcode.SUB, IROpcode.MUL,
    IROpcode.BAND, IROpcode.BOR, IROpcode.BXOR,
    IROpcode.AND, IROpcode.OR, IROpcode.NOT, IROpcode.NEG,
    IROpcode.EQ, IROpcode.NE, IROpcode.LT, IROpcode.LE, IROpcode.GT, IROpcode.GE,
    IROpcode.BUILD_LIST, IROpcode.BUILD_TUPLE, IROpcode.BUILD_DICT, IROpcode.BUILD_SET,
    IROpcode.NOP,
})

# Opcodes with side effects – never move
_SIDE_EFFECT = frozenset({
    IROpcode.STORE_NAME, IROpcode.STORE_ATTR, IROpcode.STORE_INDEX,
    IROpcode.CALL, IROpcode.RETURN, IROpcode.RAISE,
    IROpcode.JUMP, IROpcode.CJUMP, IROpcode.FOR_ITER,
    IROpcode.IMPORT_NAME, IROpcode.IMPORT_FROM, IROpcode.IMPORT_STAR,
    IROpcode.GLOBAL_DECL, IROpcode.NONLOCAL_DECL,
    IROpcode.SETUP_EXCEPT, IROpcode.END_EXCEPT,
    IROpcode.YIELD, IROpcode.YIELD_FROM,
    IROpcode.WITH_ENTER, IROpcode.WITH_EXIT,
    IROpcode.MAKE_FUNCTION, IROpcode.MAKE_CLASS,
    IROpcode.LABEL,
})

# Semantic equivalence substitutions
# Each entry: (original_op, transform_fn(instr, tmp_fn) → [IRInstruction])
def _sub_add_neg(instr: IRInstruction, tmp) -> List[IRInstruction]:
    """a + b  →  -((-a) + (-b)) * -1 ... simplified: just emit sub(-a, -b)"""
    neg_a = tmp(); neg_b = tmp(); neg_sum = tmp(); result = tmp()
    return [
        IRInstruction(IROpcode.NEG, dest=neg_a, src1=instr.src1),
        IRInstruction(IROpcode.NEG, dest=neg_b, src1=instr.src2),
        IRInstruction(IROpcode.ADD, dest=neg_sum, src1=neg_a, src2=neg_b),
        IRInstruction(IROpcode.NEG, dest=instr.dest, src1=neg_sum),
    ]

def _sub_sub_add(instr: IRInstruction, tmp) -> List[IRInstruction]:
    """a - b  →  a + (-b)"""
    neg_b = tmp()
    return [
        IRInstruction(IROpcode.NEG, dest=neg_b, src1=instr.src2),
        IRInstruction(IROpcode.ADD, dest=instr.dest, src1=instr.src1, src2=neg_b),
    ]

def _sub_bxor_band(instr: IRInstruction, tmp) -> List[IRInstruction]:
    """a ^ b  →  (a | b) & ~(a & b)  (standard identity)"""
    a_or_b  = tmp(); a_and_b = tmp(); not_ab = tmp()
    return [
        IRInstruction(IROpcode.BOR,  dest=a_or_b,  src1=instr.src1, src2=instr.src2),
        IRInstruction(IROpcode.BAND, dest=a_and_b, src1=instr.src1, src2=instr.src2),
        IRInstruction(IROpcode.BNOT, dest=not_ab,  src1=a_and_b),
        IRInstruction(IROpcode.BAND, dest=instr.dest, src1=a_or_b, src2=not_ab),
    ]

_SUBSTITUTIONS = {
    IROpcode.ADD: [_sub_add_neg],
    IROpcode.SUB: [_sub_sub_add],
    IROpcode.BXOR: [_sub_bxor_band],
}


class IRMutator:
    """
    Applies random semantics-preserving mutations to an IR copy.
    """

    def __init__(
        self,
        seed:          int   = 0,
        reorder_prob:  float = 0.3,   # probability of reordering a safe window
        junk_prob:     float = 0.25,  # probability of inserting dead compute
        subst_prob:    float = 0.2,   # probability of substituting an instruction
        rename_tmps:   bool  = True,
        label_prefix:  str   = "",    # e.g. "M_" or "S_"
    ):
        self._rng          = random.Random(seed)
        self._reorder_prob = reorder_prob
        self._junk_prob    = junk_prob
        self._subst_prob   = subst_prob
        self._rename_tmps  = rename_tmps
        self._prefix       = label_prefix
        self._tmp_ctr      = 0

    def mutate(self, module: IRModule) -> IRModule:
        for fn in module.functions.values():
            self._mutate_fn(fn)
        for cls in module.classes.values():
            for method in cls.methods.values():
                self._mutate_fn(method)
        module.module_instrs = self._mutate_instrs(module.module_instrs)
        return module

    # ── function-level mutation ───────────────────────────────────────────────

    def _mutate_fn(self, fn: IRFunction):
        fn.instructions = self._mutate_instrs(fn.instructions)
        if self._rename_tmps:
            fn.instructions = self._rename_temporaries(fn.instructions)
        for nested in fn.nested.values():
            self._mutate_fn(nested)

    def _mutate_instrs(self, instrs: List[IRInstruction]) -> List[IRInstruction]:
        instrs = self._inject_junk(instrs)
        instrs = self._substitute(instrs)
        instrs = self._reorder(instrs)
        instrs = self._rename_labels(instrs)
        return instrs

    # ── reordering ───────────────────────────────────────────────────────────

    def _reorder(self, instrs: List[IRInstruction]) -> List[IRInstruction]:
        """Identify windows of reorderable instructions and shuffle them."""
        result = []
        window: List[IRInstruction] = []

        def flush():
            if len(window) > 1 and self._rng.random() < self._reorder_prob:
                self._rng.shuffle(window)
            result.extend(window)
            window.clear()

        for instr in instrs:
            if instr.op in _SIDE_EFFECT or instr.op in (IROpcode.CJUMP, IROpcode.JUMP):
                flush()
                result.append(instr)
            elif instr.op in _REORDERABLE:
                window.append(instr)
            else:
                flush()
                result.append(instr)

        flush()
        return result

    # ── junk injection ────────────────────────────────────────────────────────

    def _inject_junk(self, instrs: List[IRInstruction]) -> List[IRInstruction]:
        result = []
        for instr in instrs:
            result.append(instr)
            if (instr.op in _REORDERABLE
                    and self._rng.random() < self._junk_prob):
                result.extend(self._make_junk_instrs())
        return result

    def _make_junk_instrs(self) -> List[IRInstruction]:
        """Dead computations – results are never used."""
        t1 = self._newtmp(); t2 = self._newtmp(); t3 = self._newtmp()
        ops = [
            [IRInstruction(IROpcode.LOAD_CONST, dest=t1,
                           meta={"value": self._rng.randint(-9999, 9999)}),
             IRInstruction(IROpcode.LOAD_CONST, dest=t2,
                           meta={"value": self._rng.randint(-9999, 9999)}),
             IRInstruction(IROpcode.ADD, dest=t3, src1=t1, src2=t2)],
            [IRInstruction(IROpcode.LOAD_CONST, dest=t1, meta={"value": True}),
             IRInstruction(IROpcode.NOT, dest=t2, src1=t1)],
            [IRInstruction(IROpcode.NOP)],
        ]
        return self._rng.choice(ops)

    def _newtmp(self) -> str:
        self._tmp_ctr += 1
        return f"$dead_{self._tmp_ctr}"

    # ── substitution ─────────────────────────────────────────────────────────

    def _substitute(self, instrs: List[IRInstruction]) -> List[IRInstruction]:
        result = []
        for instr in instrs:
            subs = _SUBSTITUTIONS.get(instr.op)
            if subs and self._rng.random() < self._subst_prob:
                fn = self._rng.choice(subs)
                expanded = fn(instr, self._newtmp)
                result.extend(expanded)
            else:
                result.append(instr)
        return result

    # ── label renaming ────────────────────────────────────────────────────────

    def _rename_labels(self, instrs: List[IRInstruction]) -> List[IRInstruction]:
        if not self._prefix:
            return instrs
        for instr in instrs:
            if instr.op is IROpcode.LABEL:
                if "name" in instr.meta:
                    instr.meta["name"] = self._prefix + instr.meta["name"]
            elif instr.op is IROpcode.JUMP:
                if "target" in instr.meta:
                    instr.meta["target"] = self._prefix + instr.meta["target"]
            elif instr.op is IROpcode.CJUMP:
                for k in ("true", "false", "handler"):
                    if k in instr.meta:
                        instr.meta[k] = self._prefix + instr.meta[k]
            elif instr.op is IROpcode.FOR_ITER:
                if "end" in instr.meta:
                    instr.meta["end"] = self._prefix + instr.meta["end"]
        return instrs

    # ── tmp renaming ─────────────────────────────────────────────────────────

    def _rename_temporaries(self, instrs: List[IRInstruction]) -> List[IRInstruction]:
        """Rename all $tN temporaries to obfuscated names."""
        name_map: Dict[str, str] = {}
        counter  = [0]

        def remap(name: Optional[str]) -> Optional[str]:
            if name is None or not name.startswith("$"):
                return name
            if name not in name_map:
                counter[0] += 1
                name_map[name] = f"$_{self._prefix}{counter[0]:04x}"
            return name_map[name]

        from typing import Optional
        for instr in instrs:
            instr.dest = remap(instr.dest)
            instr.src1 = remap(instr.src1)
            instr.src2 = remap(instr.src2)
            # remap in meta args lists
            if "args" in instr.meta:
                instr.meta["args"] = [
                    (flag, remap(v)) if isinstance(v, str) else (flag, v)
                    for flag, v in instr.meta["args"]
                ] if isinstance(instr.meta["args"], list) and instr.meta["args"] and isinstance(instr.meta["args"][0], tuple) else instr.meta["args"]
            if "items" in instr.meta:
                instr.meta["items"] = [remap(v) if isinstance(v, str) else v
                                       for v in instr.meta["items"]]
        return instrs


# ─── convenience ─────────────────────────────────────────────────────────────

def duplicate_ir(module: IRModule) -> tuple[IRModule, IRModule]:
    """Return (ir_main, ir_shadow) deep clones."""
    return IRDuplicator().duplicate(module)


def mutate_ir(
    ir_main:   IRModule,
    ir_shadow: IRModule,
    seed: int = 42,
) -> tuple[IRModule, IRModule]:
    """Apply different mutations to main and shadow copies."""
    IRMutator(seed=seed,     label_prefix="M_").mutate(ir_main)
    IRMutator(seed=seed+1,   label_prefix="S_").mutate(ir_shadow)
    return ir_main, ir_shadow
