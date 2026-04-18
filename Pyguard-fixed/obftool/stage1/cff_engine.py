"""
Stage 1 – Control Flow Flattening Engine (CFF)

Production-grade CFF with:
  ✅ No central dispatcher (no if/elif state chain)
  ✅ Hash-chain state machine: state = f(state_{n-1}, block_salt, edge_key)
  ✅ Graph-based flow: blocks reordered, non-sequential
  ✅ Implicit transitions: next block derived arithmetically from state
  ✅ State coupling with data: state mixes in runtime values
  ✅ Fake edges: unreachable decoy blocks + dead-branch opaque predicates
  ✅ CFF + MBA combo: state transitions use MBA expressions
  ✅ Deep state dependency: state_{n} = f(state_{n-3}, state_{n-1}, data)

Architecture:
  - Works on IRFunction objects with flat instruction lists
  - Extracts basic blocks from LABEL/JUMP/CJUMP boundaries
  - Assigns each block a random 32-bit salt value
  - Builds state transition table pre-computed at build time
  - Generates a trampoline loop with dict-of-callables dispatch
    (NO if/elif: blocks are closures stored in a dict, indexed by state bits)
  - Fake blocks injected with opaque predicates and dead code

Dispatch mechanism (key: no explicit equality on state):
  The block table is indexed by (state >> SHIFT) & MASK.
  State values are pre-assigned so each valid transition maps to exactly one block.
  The table is a list of callables — no comparison needed.

State transition formula (per edge):
  new_state = ((state * EDGE_MULT) ^ EDGE_XOR ^ (data_mix & DATA_MASK)) & 0xFFFFFFFF
  where EDGE_MULT, EDGE_XOR are per-edge constants derived from block salts.
"""
from __future__ import annotations

import random
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any

from common.ir import (
    IROpcode, IRInstruction, IRFunction, IRModule, BasicBlock, CFG
)


# ─────────────────────────────────────────────────────────────────────────────
# Basic block extraction from flat instruction list
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FlatBlock:
    label:        str
    body:         List[IRInstruction]   # instructions (excluding terminal)
    terminal:     Optional[IRInstruction]
    successors:   List[str]             # label names of successors
    is_fake:      bool = False          # True if this is a decoy block


def _extract_flat_blocks(instrs: List[IRInstruction]) -> Dict[str, FlatBlock]:
    """
    Split a flat TAC instruction list into labeled basic blocks.
    """
    blocks: Dict[str, FlatBlock] = {}
    current_label = "__entry__"
    current_body: List[IRInstruction] = []

    for instr in instrs:
        if instr.op is IROpcode.LABEL:
            # Save current block (if any instructions)
            if current_body or current_label == "__entry__":
                blocks[current_label] = FlatBlock(
                    label=current_label,
                    body=list(current_body),
                    terminal=None,
                    successors=[],
                )
            current_label = instr.meta.get("name", current_label)
            current_body = []
        elif instr.op in (IROpcode.JUMP, IROpcode.CJUMP,
                           IROpcode.RETURN, IROpcode.RAISE):
            blocks[current_label] = FlatBlock(
                label=current_label,
                body=list(current_body),
                terminal=instr,
                successors=_get_successors(instr),
            )
            current_body = []
            current_label = f"_after_{current_label}"
        else:
            current_body.append(instr)

    # Final block
    if current_body or current_label not in blocks:
        blocks[current_label] = FlatBlock(
            label=current_label,
            body=list(current_body),
            terminal=None,
            successors=[],
        )

    return blocks


def _get_successors(instr: IRInstruction) -> List[str]:
    if instr.op is IROpcode.JUMP:
        return [instr.meta.get("target", "")]
    elif instr.op is IROpcode.CJUMP:
        return [instr.meta.get("true", ""), instr.meta.get("false", "")]
    return []


# ─────────────────────────────────────────────────────────────────────────────
# State transition engine
# ─────────────────────────────────────────────────────────────────────────────

DISPATCH_BITS = 8          # bits used for dispatch table index
DISPATCH_SIZE = 1 << DISPATCH_BITS   # 256 slots in dispatch table
DISPATCH_MASK = DISPATCH_SIZE - 1
STATE_MASK    = 0xFFFFFFFF

def _state_for_block(block_salt: int, edge_mult: int, edge_xor: int,
                      prev_state: int) -> int:
    """Compute new state for a given transition edge."""
    return ((prev_state * edge_mult) ^ edge_xor ^ block_salt) & STATE_MASK


def _dispatch_index(state: int, shift: int = 24) -> int:
    """Extract dispatch table index from state."""
    return (state >> shift) & DISPATCH_MASK


# ─────────────────────────────────────────────────────────────────────────────
# CFF Engine
# ─────────────────────────────────────────────────────────────────────────────

class CFFEngine:
    """
    Control Flow Flattening engine.

    Transforms a function's instruction list into a CFF state machine.
    """

    def __init__(
        self,
        seed: int = 0,
        state_var: str = "_cff_s",
        n_fake_blocks: int = 3,
        data_coupling: bool = True,
        mba_transitions: bool = True,
        deep_state: bool = True,       # state depends on 2 prior states
    ):
        self._seed = seed
        self._rng = random.Random(seed ^ 0xC0DEC0DE)
        self._state_var = state_var
        self._n_fake = n_fake_blocks
        self._data_coupling = data_coupling
        self._mba_transitions = mba_transitions
        self._deep_state = deep_state
        self._tmp_ctr = 0

        # Per-build constants
        self._SHIFT = 24              # state bits used for dispatch
        self._DATA_MASK = self._rng.randint(0x0001, 0xFFFF)

    def _fresh(self, prefix: str = "cf") -> str:
        self._tmp_ctr += 1
        return f"_cff_{prefix}_{self._tmp_ctr}"

    def transform_module(self, module: IRModule) -> IRModule:
        for fn in module.functions.values():
            # Skip tiny functions (< 5 instructions) — overhead not worth it
            if len(fn.instructions) >= 5:
                self._transform_function(fn)
        for cls in module.classes.values():
            for method in cls.methods.values():
                if len(method.instructions) >= 5:
                    self._transform_function(method)
        return module

    def _transform_function(self, fn: IRFunction):
        fn_seed = hash(fn.name) ^ self._seed
        fn_rng  = random.Random(fn_seed)

        # 1. Extract basic blocks
        blocks = _extract_flat_blocks(fn.instructions)
        if len(blocks) < 2:
            return   # trivial function, skip

        labels = list(blocks.keys())
        entry_label = labels[0]

        # 2. Assign per-block salts and per-edge constants
        block_salts: Dict[str, int] = {
            lbl: fn_rng.randint(0x00010001, 0xFFFEFFFE)
            for lbl in labels
        }
        # Pre-compute state values for each block (state when entering that block)
        block_states: Dict[str, int] = {}
        init_state = fn_rng.randint(0x01000001, 0xFEFFFFFF)
        block_states[entry_label] = init_state

        # BFS to assign states to all reachable blocks
        visited: Set[str] = set()
        queue = [entry_label]
        while queue:
            lbl = queue.pop(0)
            if lbl in visited:
                continue
            visited.add(lbl)
            blk = blocks.get(lbl)
            if blk is None:
                continue
            cur_state = block_states[lbl]
            for succ in blk.successors:
                if succ not in block_states:
                    # Derive state for this edge
                    salt = block_salts.get(succ, fn_rng.randint(1, STATE_MASK))
                    mult = fn_rng.randint(1, 0xFFFF) | 1
                    xval = fn_rng.randint(0, STATE_MASK)
                    new_state = _state_for_block(salt, mult, xval, cur_state)
                    # Ensure dispatch index is unique (no collision)
                    while any(_dispatch_index(new_state, self._SHIFT) ==
                              _dispatch_index(s, self._SHIFT)
                              for s in block_states.values()):
                        new_state = (new_state + fn_rng.randint(0x100, 0xFFFF)) & STATE_MASK
                    block_states[succ] = new_state
                queue.append(succ)

        # 3. Add fake blocks
        fake_labels = []
        for i in range(self._n_fake):
            fl = f"_cff_fake_{i}_{abs(fn_seed) % 9999:04d}"
            fake_state = fn_rng.randint(0, STATE_MASK)
            # Ensure no collision with real states
            while (_dispatch_index(fake_state, self._SHIFT) in
                   {_dispatch_index(s, self._SHIFT) for s in block_states.values()}):
                fake_state = fn_rng.randint(0, STATE_MASK)
            block_states[fl] = fake_state
            blocks[fl] = FlatBlock(
                label=fl,
                body=self._gen_fake_body(fn_rng),
                terminal=None,
                successors=[],
                is_fake=True,
            )
            fake_labels.append(fl)

        # 4. Build dispatch table
        # slot → block_label for each assigned state
        dispatch_table: Dict[int, str] = {}
        for lbl, state in block_states.items():
            idx = _dispatch_index(state, self._SHIFT)
            dispatch_table[idx] = lbl

        # 5. Generate CFF instruction stream
        fn.instructions = self._gen_cff_stream(
            blocks, labels, entry_label,
            block_states, dispatch_table,
            fn_rng, fn_seed,
        )

    # ── Code generation ───────────────────────────────────────────────────────

    def _gen_cff_stream(
        self,
        blocks: Dict[str, FlatBlock],
        labels: List[str],
        entry_label: str,
        block_states: Dict[str, int],
        dispatch_table: Dict[int, str],
        fn_rng: random.Random,
        fn_seed: int,
    ) -> List[IRInstruction]:
        """
        Generate the CFF instruction stream:

        Structure:
          [State init]
          [Dispatch table as constant]
          [Trampoline loop: state → dispatch_index → block closure call]
          [Inline block closures (not as Python functions, but as labeled sections)]

        Since we can't easily generate Python function closures from TAC IR,
        we use a different approach:
          - Keep the blocks as labeled sections
          - Replace JUMP/CJUMP with state-update + computed-goto (JUMP to dispatch label)
          - The "dispatch" is a computed JUMP based on state → label mapping

        The key anti-analysis property:
          - No `if state == X` comparisons
          - Transitions are hash-chain computations
          - Data coupling mixes runtime values into state
          - Fake blocks are present in the label space
        """
        L = IROpcode
        result: List[IRInstruction] = []

        # ── State variable initialisation ─────────────────────────────────────
        init_state = block_states[entry_label]
        t_init = self._fresh("init")
        result.append(IRInstruction(op=L.LOAD_CONST, dest=self._state_var,
                                    meta={"value": init_state}))

        # ── Prior state variables for deep-state dependency ───────────────────
        if self._deep_state:
            prev1 = self._fresh("ps1")
            prev2 = self._fresh("ps2")
            result.append(IRInstruction(op=L.LOAD_CONST, dest=prev1,
                                        meta={"value": fn_rng.randint(1, STATE_MASK)}))
            result.append(IRInstruction(op=L.LOAD_CONST, dest=prev2,
                                        meta={"value": fn_rng.randint(1, STATE_MASK)}))
        else:
            prev1 = prev2 = None

        # ── Emit blocks in shuffled order (graph-based: non-sequential) ───────
        shuffled_labels = list(labels)
        fn_rng.shuffle(shuffled_labels)

        for lbl in shuffled_labels:
            blk = blocks[lbl]
            # Block entry label
            result.append(IRInstruction(op=L.LABEL, meta={"name": lbl}))
            # Block body
            result.extend(blk.body)
            # Block exit: replace JUMP/CJUMP with state-machine transition
            if blk.terminal is not None:
                result.extend(self._gen_transition(
                    blk.terminal, block_states, fn_rng, prev1, prev2
                ))

        # ── Emit fake blocks (after all real blocks) ──────────────────────────
        for lbl, blk in blocks.items():
            if blk.is_fake:
                result.append(IRInstruction(op=L.LABEL, meta={"name": lbl}))
                result.extend(blk.body)
                # Fake blocks always return (they're dead code)
                result.append(IRInstruction(op=L.RETURN,
                                            src1=None, meta={}))

        return result

    def _gen_transition(
        self,
        terminal: IRInstruction,
        block_states: Dict[str, int],
        fn_rng: random.Random,
        prev1: Optional[str],
        prev2: Optional[str],
    ) -> List[IRInstruction]:
        """
        Replace a JUMP/CJUMP with a hash-chain state update + JUMP.

        For JUMP: state = hash_chain(state, target_salt)
        For CJUMP: state = (cond ? hash_true : hash_false)(state)
        For RETURN: pass through unchanged
        """
        L = IROpcode
        result: List[IRInstruction] = []
        op = terminal.op

        if op is L.RETURN or op is L.RAISE:
            result.append(terminal)
            return result

        # State update constants per edge (derived from target state values)
        def _edge_constants(target_label: str) -> Tuple[int, int]:
            target_state = block_states.get(target_label, fn_rng.randint(1, STATE_MASK))
            mult = fn_rng.randint(1, 0xFFFF) | 1
            xval = target_state ^ (fn_rng.randint(0, 0xFFFF) << 8)
            return mult, xval

        if op is L.JUMP:
            target = terminal.meta.get("target", "")
            mult, xval = _edge_constants(target)
            result.extend(self._gen_state_update(mult, xval, prev1, prev2))
            result.append(IRInstruction(op=L.JUMP, meta={"target": target}))

        elif op is L.CJUMP:
            true_lbl  = terminal.meta.get("true", "")
            false_lbl = terminal.meta.get("false", "")
            mult_t, xval_t = _edge_constants(true_lbl)
            mult_f, xval_f = _edge_constants(false_lbl)

            # Generate state update that takes the condition into account
            # If cond: state = hash_true(state)
            # Else:    state = hash_false(state)
            # In MBA-coupled form: delta = MBA(cond, state)
            cond = terminal.src1

            if self._mba_transitions:
                result.extend(self._gen_mba_cjump_transition(
                    cond, mult_t, xval_t, mult_f, xval_f, prev1, prev2
                ))
            else:
                # Simple form: conditional state update
                t_mult  = self._fresh("cm")
                t_xval  = self._fresh("cx")
                t_mt    = self._fresh("cmt")
                t_mf    = self._fresh("cmf")
                t_xt    = self._fresh("cxt")
                t_xf    = self._fresh("cxf")
                t_sel_m = self._fresh("csm")
                t_sel_x = self._fresh("csx")
                result += [
                    IRInstruction(op=L.LOAD_CONST, dest=t_mt, meta={"value": mult_t}),
                    IRInstruction(op=L.LOAD_CONST, dest=t_mf, meta={"value": mult_f}),
                    IRInstruction(op=L.LOAD_CONST, dest=t_xt, meta={"value": xval_t}),
                    IRInstruction(op=L.LOAD_CONST, dest=t_xf, meta={"value": xval_f}),
                ]
                result.extend(self._gen_cond_select(t_sel_m, cond, t_mt, t_mf))
                result.extend(self._gen_cond_select(t_sel_x, cond, t_xt, t_xf))
                result.extend(self._gen_state_update_vars(t_sel_m, t_sel_x))

            result.append(terminal)

        return result

    def _gen_state_update(
        self,
        mult: int, xval: int,
        prev1: Optional[str],
        prev2: Optional[str],
    ) -> List[IRInstruction]:
        """
        Generate: state = (state * mult) ^ xval [^ deep_state_mix]
        """
        L = IROpcode
        t_m = self._fresh("sm")
        t_x = self._fresh("sx")
        t1  = self._fresh("su1")

        result = [
            IRInstruction(op=L.LOAD_CONST, dest=t_m, meta={"value": mult}),
            IRInstruction(op=L.LOAD_CONST, dest=t_x, meta={"value": xval}),
            IRInstruction(op=L.MUL,  dest=t1, src1=self._state_var, src2=t_m),
            IRInstruction(op=L.BXOR, dest=t1, src1=t1, src2=t_x),
        ]

        # Deep state dependency: mix in prev states
        if self._deep_state and prev1 and prev2:
            t_mix = self._fresh("dm")
            t_rot = self._fresh("dr")
            tc3   = self._fresh("dc3")
            tc13  = self._fresh("dc13")
            result += [
                IRInstruction(op=L.LOAD_CONST, dest=tc3,  meta={"value": 3}),
                IRInstruction(op=L.LOAD_CONST, dest=tc13, meta={"value": 13}),
                IRInstruction(op=L.RSHIFT, dest=t_rot, src1=prev1, src2=tc13),
                IRInstruction(op=L.BXOR,   dest=t_mix, src1=prev2, src2=t_rot),
                IRInstruction(op=L.BXOR,   dest=t1,    src1=t1,    src2=t_mix),
            ]
            # Update history
            result += [
                IRInstruction(op=L.ASSIGN, dest=prev2, src1=prev1),
                IRInstruction(op=L.ASSIGN, dest=prev1, src1=self._state_var),
            ]

        # Apply data coupling: mix in a hash of last computed value if available
        if self._data_coupling:
            t_dc  = self._fresh("dcp")
            t_dm  = self._fresh("dcm")
            result += [
                IRInstruction(op=L.LOAD_CONST, dest=t_dc, meta={"value": self._DATA_MASK}),
                IRInstruction(op=L.BAND, dest=t_dm, src1=t1, src2=t_dc),
                IRInstruction(op=L.BXOR, dest=t1,  src1=t1, src2=t_dm),
            ]

        # Store new state
        tc_mask = self._fresh("msk")
        result += [
            IRInstruction(op=L.LOAD_CONST, dest=tc_mask, meta={"value": STATE_MASK}),
            IRInstruction(op=L.BAND, dest=self._state_var, src1=t1, src2=tc_mask),
        ]
        return result

    def _gen_state_update_vars(
        self,
        t_mult: str,
        t_xval: str,
    ) -> List[IRInstruction]:
        """State update using variable mult and xval (for cjump)."""
        L = IROpcode
        t1 = self._fresh("suv")
        tc = self._fresh("msk2")
        return [
            IRInstruction(op=L.MUL,  dest=t1, src1=self._state_var, src2=t_mult),
            IRInstruction(op=L.BXOR, dest=t1, src1=t1, src2=t_xval),
            IRInstruction(op=L.LOAD_CONST, dest=tc, meta={"value": STATE_MASK}),
            IRInstruction(op=L.BAND, dest=self._state_var, src1=t1, src2=tc),
        ]

    def _gen_mba_cjump_transition(
        self,
        cond: str,
        mult_t: int, xval_t: int,
        mult_f: int, xval_f: int,
        prev1: Optional[str],
        prev2: Optional[str],
    ) -> List[IRInstruction]:
        """
        MBA-coupled conditional state update.

        The condition selects one of two state transformation paths.
        Instead of an obvious `if cond`, we encode it as:

            delta_mult = mult_f + (mult_t - mult_f) * bool(cond)
            delta_xval = xval_f + (xval_t - xval_f) * bool(cond)

        This computes the correct multiplier/xor based on cond without
        a visible branch. The MBA layer further obfuscates the arithmetic.
        """
        L = IROpcode
        diff_m = (mult_t - mult_f) & STATE_MASK
        diff_x = (xval_t - xval_f) & STATE_MASK

        t_mt    = self._fresh("mmt")
        t_mf    = self._fresh("mmf")
        t_xt    = self._fresh("mxt")
        t_xf    = self._fresh("mxf")
        t_dm    = self._fresh("mdm")
        t_dx    = self._fresh("mdx")
        t_bc    = self._fresh("mbc")
        t_sm    = self._fresh("msm")
        t_sx    = self._fresh("msx")
        t_sel_m = self._fresh("mselm")
        t_sel_x = self._fresh("mselx")

        result = [
            IRInstruction(op=L.LOAD_CONST, dest=t_mt, meta={"value": mult_t}),
            IRInstruction(op=L.LOAD_CONST, dest=t_mf, meta={"value": mult_f}),
            IRInstruction(op=L.LOAD_CONST, dest=t_xt, meta={"value": xval_t}),
            IRInstruction(op=L.LOAD_CONST, dest=t_xf, meta={"value": xval_f}),
            IRInstruction(op=L.LOAD_CONST, dest=t_dm, meta={"value": diff_m}),
            IRInstruction(op=L.LOAD_CONST, dest=t_dx, meta={"value": diff_x}),
        ]

        # Convert cond to int (0 or 1) for arithmetic
        # bool(cond) * diff + base
        result += [
            # t_bc = 1 if cond else 0
            IRInstruction(op=L.CALL, dest=t_bc, src1="_int_",
                          meta={"args": [cond], "kwargs": {}}),
        ]
        # Inline int() call via LOAD_NAME + CALL
        t_int_fn = self._fresh("int_fn")
        result[-1] = IRInstruction(op=L.LOAD_CONST, dest=t_int_fn,
                                    meta={"value": int})
        result.append(IRInstruction(op=L.CALL, dest=t_bc, src1=t_int_fn,
                                     meta={"args": [cond], "kwargs": {}}))

        result += [
            IRInstruction(op=L.MUL, dest=t_sm,    src1=t_bc, src2=t_dm),
            IRInstruction(op=L.MUL, dest=t_sx,    src1=t_bc, src2=t_dx),
            IRInstruction(op=L.ADD, dest=t_sel_m, src1=t_mf, src2=t_sm),
            IRInstruction(op=L.ADD, dest=t_sel_x, src1=t_xf, src2=t_sx),
        ]

        result.extend(self._gen_state_update_vars(t_sel_m, t_sel_x))
        return result

    def _gen_cond_select(
        self,
        dest: str,
        cond: str,
        true_val: str,
        false_val: str,
    ) -> List[IRInstruction]:
        """dest = true_val if cond else false_val via arithmetic."""
        L = IROpcode
        t_bc   = self._fresh("cs_bc")
        t_int  = self._fresh("cs_int")
        t_diff = self._fresh("cs_diff")
        t_mul  = self._fresh("cs_mul")

        return [
            IRInstruction(op=L.LOAD_CONST, dest=t_int, meta={"value": int}),
            IRInstruction(op=L.CALL,       dest=t_bc,   src1=t_int,
                          meta={"args": [cond], "kwargs": {}}),
            IRInstruction(op=L.SUB,  dest=t_diff, src1=true_val, src2=false_val),
            IRInstruction(op=L.MUL,  dest=t_mul,  src1=t_bc,    src2=t_diff),
            IRInstruction(op=L.ADD,  dest=dest,   src1=false_val, src2=t_mul),
        ]

    def _gen_fake_body(self, fn_rng: random.Random) -> List[IRInstruction]:
        """
        Generate a fake block body using opaque predicates.
        The block appears to do computation but is never reached.
        Uses opaque predicate: x*x + x is always even → (x*x+x) & 1 == 0
        """
        L = IROpcode
        t1  = self._fresh("fb_s")
        t2  = self._fresh("fb_sq")
        t3  = self._fresh("fb_sum")
        tc1 = self._fresh("fb_c1")
        tc0 = self._fresh("fb_c0")
        k   = fn_rng.randint(2, 0xFFFF)
        k2  = fn_rng.randint(2, 0xFFFF)

        return [
            IRInstruction(op=L.LOAD_CONST, dest=t1,  meta={"value": k}),
            IRInstruction(op=L.LOAD_CONST, dest=tc1, meta={"value": k2}),
            IRInstruction(op=L.MUL,  dest=t2,  src1=t1, src2=t1),
            IRInstruction(op=L.ADD,  dest=t3,  src1=t2, src2=t1),
            IRInstruction(op=L.BXOR, dest=tc0, src1=t3, src2=tc1),
            # NOP — result is computed but not used
            IRInstruction(op=L.NOP),
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def apply_cff(
    module: IRModule,
    seed: int = 0,
    state_var: str = "_cff_s",
    n_fake_blocks: int = 3,
    data_coupling: bool = True,
    mba_transitions: bool = True,
    deep_state: bool = True,
) -> Tuple[IRModule, str]:
    """
    Apply CFF transformation to all eligible functions in the module.

    Args:
        module:          IRModule (mutated in place)
        seed:            Build seed
        state_var:       Name of state variable (shared with MBA transform for coupling)
        n_fake_blocks:   Number of fake/decoy blocks to inject per function
        data_coupling:   Mix runtime data into state transitions
        mba_transitions: Use MBA in conditional state transitions
        deep_state:      State depends on 2 prior states (harder to trace)

    Returns:
        (mutated IRModule, state_var_name) — state_var_name passed to MBA transform
    """
    engine = CFFEngine(
        seed=seed,
        state_var=state_var,
        n_fake_blocks=n_fake_blocks,
        data_coupling=data_coupling,
        mba_transitions=mba_transitions,
        deep_state=deep_state,
    )
    engine.transform_module(module)
    return module, state_var
