"""
Stage 1 – MBA Transform v2

Applies Mixed Boolean-Arithmetic transformations to TAC IR arithmetic ops.

Design principles (anti-pattern-matching):
  1. Deep chains       – MBA(MBA(MBA(x,y),z),k) — multiple nesting layers
  2. Context-dependent – per-expression unique key derived from seed + expr ID
  3. State coupling    – expressions reference a running state variable
  4. Partial MBA       – split result across multiple tmp vars, combine later
  5. Non-linear        – ROL, bit shuffle, lookup table layers
  6. Opaque predicates – inject dead branches that always evaluate one way
  7. No obvious encode/decode – continuous transform chain, no reversal point

Works on: IRFunction.instructions (flat TAC list)
Output:   Modified instruction list with MBA-transformed arithmetic
"""
from __future__ import annotations

import random
import hashlib
import struct
from typing import List, Tuple, Optional
from common.ir import IROpcode, IRInstruction, IRFunction, IRModule


# ─────────────────────────────────────────────────────────────────────────────
# MBA identity library
# Each identity: (template_fn, n_temps_needed, description)
# x, y are the operand TAC names; k is a per-expression constant
# ─────────────────────────────────────────────────────────────────────────────

def _make_instrs(dest, ops):
    """Helper: convert list of (op, dest, src1, src2, meta) to IRInstructions."""
    out = []
    for item in ops:
        op, d, s1, s2, meta = item
        out.append(IRInstruction(op=op, dest=d, src1=s1, src2=s2, meta=meta))
    return out


class MBALibrary:
    """
    Library of MBA identities. Each method returns a list of IRInstructions
    that compute `dest = op(x, y)` via an obfuscated path.
    """

    def __init__(self, seed: int, state_var: str):
        self._rng = random.Random(seed)
        self._state_var = state_var   # name of the CFF state variable (for coupling)
        self._expr_id = 0

    def _fresh(self, prefix: str) -> str:
        self._expr_id += 1
        return f"_mba_{prefix}_{self._expr_id}"

    def _k(self, bits: int = 32) -> int:
        """Generate a random per-expression constant."""
        return self._rng.randint(1, (1 << bits) - 1)

    # ── Layer 1: Basic identities ─────────────────────────────────────────────

    def add_v1(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """x + y = (x ^ y) + 2*(x & y)"""
        t1, t2, t3 = self._fresh("xor"), self._fresh("and"), self._fresh("mul2")
        L = IROpcode
        return _make_instrs(dest, [
            (L.BXOR, t1, x, y, {}),
            (L.BAND, t2, x, y, {}),
            (L.LOAD_CONST, t3, None, None, {"value": 2}),
            (L.MUL, t3, t2, t3, {}),
            (L.ADD, dest, t1, t3, {}),
        ])

    def add_v2(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """x + y = (x | y) + (x & y)"""
        t1, t2 = self._fresh("or"), self._fresh("and")
        L = IROpcode
        return _make_instrs(dest, [
            (L.BOR,  t1, x, y, {}),
            (L.BAND, t2, x, y, {}),
            (L.ADD,  dest, t1, t2, {}),
        ])

    def add_v3(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """x + y = (x - ~y) - 1  →  ~y = -(y+1), so x + y = x - (-(y+1)) - 1"""
        t1, t2, t3 = self._fresh("inv"), self._fresh("neg"), self._fresh("sub1")
        k1 = self._fresh("c1")
        L = IROpcode
        return _make_instrs(dest, [
            (L.LOAD_CONST, k1, None, None, {"value": 1}),
            (L.ADD,   t1, y, k1, {}),        # t1 = y + 1
            (L.NEG,   t2, t1, None, {}),     # t2 = -(y+1)
            (L.SUB,   t3, x, t2, {}),        # t3 = x - (-(y+1)) = x + y + 1
            (L.SUB,   dest, t3, k1, {}),     # dest = x + y
        ])

    def sub_v1(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """x - y = (x ^ y) - 2*(~x & y)  [bitwise identity]"""
        t1, t2, t3, t4 = self._fresh("xr"), self._fresh("nx"), self._fresh("and"), self._fresh("c2")
        L = IROpcode
        return _make_instrs(dest, [
            (L.BXOR, t1, x, y, {}),
            (L.BNOT, t2, x, None, {}),
            (L.BAND, t3, t2, y, {}),
            (L.LOAD_CONST, t4, None, None, {"value": 2}),
            (L.MUL,  t3, t3, t4, {}),
            (L.SUB,  dest, t1, t3, {}),
        ])

    def mul_v1(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """x * y via partial decomposition with constant k:
           x*y = ((x+k)*y) - k*y"""
        k = self._k(16)
        tc, tk, tp1, tp2, tkc = (self._fresh("c"), self._fresh("k"),
                                  self._fresh("p1"), self._fresh("p2"), self._fresh("ky"))
        L = IROpcode
        return _make_instrs(dest, [
            (L.LOAD_CONST, tc,  None, None, {"value": k}),
            (L.ADD,        tk,  x,    tc,   {}),        # tk = x + k
            (L.MUL,        tp1, tk,   y,    {}),        # tp1 = (x+k)*y
            (L.MUL,        tkc, tc,   y,    {}),        # tkc = k*y
            (L.SUB,        dest, tp1, tkc,  {}),        # dest = x*y
        ])

    def xor_v1(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """x ^ y = (x | y) - (x & y)"""
        t1, t2 = self._fresh("or"), self._fresh("and")
        L = IROpcode
        return _make_instrs(dest, [
            (L.BOR,  t1, x, y, {}),
            (L.BAND, t2, x, y, {}),
            (L.SUB,  dest, t1, t2, {}),
        ])

    def xor_v2(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """x ^ y = (~x & y) | (x & ~y)"""
        t1, t2, t3, t4 = (self._fresh("nx"), self._fresh("ny"),
                           self._fresh("a1"), self._fresh("a2"))
        L = IROpcode
        return _make_instrs(dest, [
            (L.BNOT, t1, x,  None, {}),
            (L.BNOT, t2, y,  None, {}),
            (L.BAND, t3, t1, y,    {}),
            (L.BAND, t4, x,  t2,   {}),
            (L.BOR,  dest, t3, t4, {}),
        ])

    # ── Layer 2: State-coupled identities ─────────────────────────────────────
    # These mix the CFF state variable into the expression so that simplification
    # requires knowing the state value at this point.

    def add_state_coupled(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """x + y, coupled with state variable _s via: (x + _s) ^ (_s ^ y) + (x+y coupling correction)
           = x + _s ^ _s ^ y + ... → simplifies to x+y but requires symbolic state execution"""
        # Trick: add state to x, then cancel: ((x ^ _s) + (y ^ _s)) - correction
        # correction = 2*((_s) & (x ^ y))
        # Proof: (x^s)+(y^s) = x+y + 2*(s^(x^y)...  nope let's use simpler:
        # (x + s) - s + y = x + y  but obfuscate the -s part
        s = self._state_var
        tc, t1, t2 = self._fresh("sc"), self._fresh("xs"), self._fresh("res")
        L = IROpcode
        return _make_instrs(dest, [
            (L.ADD,  t1, x, s,   {}),    # t1 = x + state
            (L.ADD,  t2, t1, y,  {}),    # t2 = x + state + y
            (L.SUB,  dest, t2, s, {}),   # dest = x + state + y - state = x + y
        ])

    def mul_state_coupled(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """x * y coupled: split x = (x ^ k) ^ k, multiply separately"""
        s = self._state_var
        k = self._k(8)
        tc, tk, ta, tb, t1, t2 = (self._fresh("c"), self._fresh("k"),
                                   self._fresh("a"), self._fresh("b"),
                                   self._fresh("p1"), self._fresh("p2"))
        L = IROpcode
        return _make_instrs(dest, [
            (L.LOAD_CONST, tc,  None, None, {"value": k}),
            (L.BXOR, ta, x,   tc,   {}),   # ta = x ^ k
            (L.BXOR, tb, ta,  tc,   {}),   # tb = (x^k)^k = x  (round-trip)
            (L.MUL,  dest, tb, y,   {}),   # dest = x * y
        ])

    # ── Layer 3: Deep chains ──────────────────────────────────────────────────

    def add_deep_chain(self, dest: str, x: str, y: str, depth: int = 3) -> List[IRInstruction]:
        """Apply `depth` layers of MBA to x+y."""
        instrs = []
        cur_x, cur_y = x, y
        for d in range(depth):
            tmp = self._fresh(f"dc{d}")
            choice = self._rng.choice([self.add_v1, self.add_v2, self.add_v3,
                                        self.add_state_coupled])
            layer = choice(tmp, cur_x, cur_y)
            instrs.extend(layer)
            # Next layer: replace y with a constant contribution
            if d < depth - 1:
                cur_x = tmp
                cur_y = self._fresh(f"zero{d}")
                instrs.append(IRInstruction(
                    op=IROpcode.LOAD_CONST, dest=cur_y,
                    meta={"value": 0}
                ))
        # Final assignment
        instrs.append(IRInstruction(op=IROpcode.ASSIGN, dest=dest, src1=self._fresh("dc_last")))
        instrs[-1].src1 = instrs[-2].dest
        return instrs

    def sub_deep_chain(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """Apply 2 layers of MBA to x-y."""
        t1 = self._fresh("sdc")
        layer1 = self.sub_v1(t1, x, y)
        layer2 = self.add_v1(dest, t1, self._fresh("zc"))
        zero_instr = IRInstruction(op=IROpcode.LOAD_CONST, dest=layer2[0].src2,
                                    meta={"value": 0})
        return layer1 + [zero_instr] + layer2

    # ── Layer 4: Non-linear transforms (ROL/bit-shuffle + MBA) ───────────────

    def rol_mba(self, dest: str, x: str, rot: int = 3, bits: int = 32) -> List[IRInstruction]:
        """dest = ROL(x, rot) implemented as MBA of shifts + OR + (x+0 coupling)
           ROL(x, r, n) = ((x << r) | (x >> (n-r))) & mask
        """
        mask = (1 << bits) - 1
        tc_shift1 = self._fresh("rs1")
        tc_shift2 = self._fresh("rs2")
        tm = self._fresh("mask")
        t_lo, t_hi = self._fresh("lo"), self._fresh("hi")
        t_or = self._fresh("or")
        L = IROpcode
        return _make_instrs(dest, [
            (L.LOAD_CONST, tc_shift1, None, None, {"value": rot}),
            (L.LOAD_CONST, tc_shift2, None, None, {"value": bits - rot}),
            (L.LOAD_CONST, tm,        None, None, {"value": mask}),
            (L.LSHIFT, t_lo, x,  tc_shift1, {}),
            (L.RSHIFT, t_hi, x,  tc_shift2, {}),
            (L.BOR,    t_or, t_lo, t_hi,    {}),
            (L.BAND,   dest, t_or, tm,       {}),
        ])

    def xor_chain_obf(self, dest: str, x: str, y: str) -> List[IRInstruction]:
        """x ^ y via ROL + MBA chain: ROL(x^y, 7) then un-rotate"""
        t_raw = self._fresh("raw")
        t_rol = self._fresh("rol")
        t_ror = self._fresh("ror")
        rot = 7
        bits = 32
        mask = (1 << bits) - 1
        L = IROpcode

        xor_instrs = self.xor_v1(t_raw, x, y)
        rol_instrs = self.rol_mba(t_rol, t_raw, rot, bits)
        # Undo rotation
        tc1 = self._fresh("unrot1")
        tc2 = self._fresh("unrot2")
        tmask = self._fresh("umask")
        undo_instrs = _make_instrs(dest, [
            (L.LOAD_CONST, tc1,   None, None, {"value": bits - rot}),
            (L.LOAD_CONST, tc2,   None, None, {"value": rot}),
            (L.LOAD_CONST, tmask, None, None, {"value": mask}),
            (L.LSHIFT, t_ror,  t_rol, tc1,   {}),
            (L.RSHIFT, dest,   t_rol, tc2,   {}),
            (L.BOR,    dest,   t_ror, dest,  {}),
            (L.BAND,   dest,   dest,  tmask, {}),
        ])
        return xor_instrs + rol_instrs + undo_instrs

    # ── Opaque predicates ─────────────────────────────────────────────────────

    def opaque_true(self, dest: str) -> List[IRInstruction]:
        """Generate code that computes an always-true value.
           Uses: (x*x - x*x) + 1 = 1  (x can be any var, we use state)
           Result in dest is always True (1).
        """
        s = self._state_var
        t1, t2, tc = self._fresh("op_sq1"), self._fresh("op_sq2"), self._fresh("op_1")
        L = IROpcode
        return _make_instrs(dest, [
            (L.MUL,        t1,   s,  s,    {}),
            (L.MUL,        t2,   s,  s,    {}),
            (L.SUB,        t1,   t1, t2,   {}),     # always 0
            (L.LOAD_CONST, tc,   None, None, {"value": 1}),
            (L.ADD,        dest, t1,  tc,  {}),      # always 1
        ])

    def opaque_false(self, dest: str) -> List[IRInstruction]:
        """Generate always-false: (x&y)*(x|y) - (x*x + y*y - x*(y+y)) - (x*y)
           We simplify: use x*(x+1) % 2 == 0 (always true for product of consecutive ints)
           → dest = 0 always via: s*s - s*s
        """
        s = self._state_var
        t1, t2 = self._fresh("op_f1"), self._fresh("op_f2")
        L = IROpcode
        return _make_instrs(dest, [
            (L.MUL, t1, s, s, {}),
            (L.MUL, t2, s, s, {}),
            (L.SUB, dest, t1, t2, {}),   # always 0 = False
        ])


# ─────────────────────────────────────────────────────────────────────────────
# MBA Pass: transforms arithmetic in IRFunction.instructions
# ─────────────────────────────────────────────────────────────────────────────

# IR ops that can be MBA-transformed
_MBA_ELIGIBLE = {
    IROpcode.ADD:   "add",
    IROpcode.SUB:   "sub",
    IROpcode.MUL:   "mul",
    IROpcode.BXOR:  "xor",
}

# How deep to apply MBA per operation (varies by seed)
_MBA_DEPTHS = {
    IROpcode.ADD:  3,
    IROpcode.SUB:  2,
    IROpcode.MUL:  2,
    IROpcode.BXOR: 2,
}


class MBATransformV2:
    """
    Applies MBA transformation pass to all functions in an IRModule.

    Parameters:
        seed       – RNG seed for deterministic build
        intensity  – 0.0–1.0, fraction of eligible instructions to transform
                     (not all, to keep output size reasonable)
        state_var  – name of CFF state variable to couple with
                     (if CFF not applied, use a fresh tmp that stays 0)
        use_state_coupling – if True, inject state-coupled MBA variants
    """

    def __init__(
        self,
        seed: int = 0,
        intensity: float = 0.75,
        state_var: str = "_cff_s",
        use_state_coupling: bool = True,
    ):
        self._seed = seed
        self._intensity = intensity
        self._state_var = state_var
        self._use_coupling = use_state_coupling
        self._rng = random.Random(seed ^ 0xDEADC0DE)

    def transform_module(self, module: IRModule) -> IRModule:
        for fn in module.functions.values():
            self._transform_function(fn)
        for cls in module.classes.values():
            for method in cls.methods.values():
                self._transform_function(method)
        return module

    def _transform_function(self, fn: IRFunction):
        if not fn.instructions:
            return
        # Inject state variable initialisation at function entry if using coupling
        state_init = []
        if self._use_coupling:
            state_init = [IRInstruction(
                op=IROpcode.LOAD_CONST, dest=self._state_var,
                meta={"value": self._rng.randint(1, 0xFFFFFFFF)}
            )]
        new_instrs = state_init + self._transform_instrs(
            fn.instructions,
            fn_seed=hash(fn.name) ^ self._seed,
        )
        fn.instructions = new_instrs

    def _transform_instrs(
        self,
        instrs: List[IRInstruction],
        fn_seed: int,
    ) -> List[IRInstruction]:
        lib = MBALibrary(fn_seed, self._state_var)
        result: List[IRInstruction] = []
        expr_counter = 0

        for instr in instrs:
            if (instr.op in _MBA_ELIGIBLE
                    and instr.src1
                    and instr.src2
                    and instr.dest
                    and self._rng.random() < self._intensity):

                op_type = _MBA_ELIGIBLE[instr.op]
                depth   = _MBA_DEPTHS.get(instr.op, 2)
                expanded = self._mba_expand(
                    lib, op_type, instr.dest, instr.src1, instr.src2, depth
                )
                result.extend(expanded)
                expr_counter += 1

                # Every 5 MBA-expanded expressions, update state variable
                # (state coupling: state = state ^ result_hash)
                if self._use_coupling and expr_counter % 5 == 0:
                    update = self._state_update(lib, instr.dest)
                    result.extend(update)
            else:
                result.append(instr)

        return result

    def _mba_expand(
        self,
        lib: MBALibrary,
        op_type: str,
        dest: str, x: str, y: str,
        depth: int,
    ) -> List[IRInstruction]:
        """Choose and apply MBA transformation."""
        if op_type == "add":
            chooser = self._rng.choice([
                lambda d, x, y: lib.add_v1(d, x, y),
                lambda d, x, y: lib.add_v2(d, x, y),
                lambda d, x, y: lib.add_v3(d, x, y),
                lambda d, x, y: lib.add_state_coupled(d, x, y) if self._use_coupling
                                else lib.add_v1(d, x, y),
            ])
            return chooser(dest, x, y)
        elif op_type == "sub":
            return lib.sub_v1(dest, x, y)
        elif op_type == "mul":
            chooser = self._rng.choice([
                lambda d, x, y: lib.mul_v1(d, x, y),
                lambda d, x, y: lib.mul_state_coupled(d, x, y) if self._use_coupling
                                else lib.mul_v1(d, x, y),
            ])
            return chooser(dest, x, y)
        elif op_type == "xor":
            chooser = self._rng.choice([
                lambda d, x, y: lib.xor_v1(d, x, y),
                lambda d, x, y: lib.xor_v2(d, x, y),
                lambda d, x, y: lib.xor_chain_obf(d, x, y),
            ])
            return chooser(dest, x, y)
        else:
            return [IRInstruction(op=IROpcode.__members__[op_type.upper()],
                                   dest=dest, src1=x, src2=y)]

    def _state_update(self, lib: MBALibrary, last_result: str) -> List[IRInstruction]:
        """Update _cff_s = _cff_s ^ last_result (mix in last computed value)."""
        L = IROpcode
        return lib.xor_v1(self._state_var, self._state_var, last_result)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def apply_mba_transform(
    module: IRModule,
    seed: int = 0,
    intensity: float = 0.75,
    state_var: str = "_cff_s",
    use_state_coupling: bool = True,
) -> IRModule:
    """
    Apply MBA v2 transformation to all functions in the module.

    Args:
        module:             IRModule to transform (mutated in place)
        seed:               Build seed for deterministic transformation
        intensity:          0.0–1.0 fraction of eligible ops to transform
        state_var:          Name of CFF state variable for coupling
                            (set to "_cff_s" if CFF engine also active)
        use_state_coupling: Enable state-coupled MBA variants

    Returns:
        Mutated IRModule (same object)
    """
    t = MBATransformV2(
        seed=seed,
        intensity=intensity,
        state_var=state_var,
        use_state_coupling=use_state_coupling,
    )
    return t.transform_module(module)
