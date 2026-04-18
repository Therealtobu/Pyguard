"""
Module 2.2 – SR-VM Opcode Polymorphic Generator (RUNTIME)

Runtime polymorphism model:
  1. HANDLER POOL  – each logical operation has N functionally-equivalent
     handler implementations. At VM startup a random one is selected.
  2. DISPATCH SHUFFLE – the mapping from physical opcode byte to logical
     operation is permuted at startup using a runtime-derived seed.
  3. ASLR XOR LAYER – decoded bytecode bytes are XOR'd in-memory with a
     pad derived from id(object()) (changes with ASLR every run).

Result:
  • Static file analysis: sees only encrypted ciphertext.
  • Memory dump after load: bytecode bytes differ every run (ASLR XOR).
  • Breakpoint on handler: different call targets every run (handler rotation).
  • Code coverage: handler pool makes profiling mislead analysts.
"""

from __future__ import annotations
import os
import time
import struct
import random
import hashlib
import ctypes
from enum import IntEnum
from typing import Dict, List, Callable, Any, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Logical Opcode Definitions
# ─────────────────────────────────────────────────────────────────────────────

class LogicalOp(IntEnum):
    # ── Stack / register data movement ───────────────────────────────────────
    NOP          = 0x00
    PUSH_CONST   = 0x01   # push constant[operand]
    PUSH_REG     = 0x02   # push R[operand]
    POP_REG      = 0x03   # R[operand] = pop()
    POP_DISCARD  = 0x04   # pop and discard
    DUP_TOP      = 0x05   # duplicate stack top
    ROT_TWO      = 0x06   # swap top two
    ROT_THREE    = 0x07   # rotate top three
    LOAD_NAME    = 0x08   # push env[name_table[operand]]
    STORE_NAME   = 0x09   # env[name_table[operand]] = pop()
    LOAD_ATTR    = 0x0A   # top = getattr(pop(), name_table[operand])
    STORE_ATTR   = 0x0B   # setattr(stack[-2], name_table[operand], pop())
    LOAD_INDEX   = 0x0C   # idx=pop(); top=pop()[idx]
    STORE_INDEX  = 0x0D   # v=pop(); idx=pop(); obj=pop(); obj[idx]=v
    DELETE_NAME  = 0x0E   # del env[name_table[operand]]

    # ── Arithmetic (SS = Stack+Stack, SR = Stack+Reg, RR = Reg+Reg) ──────────
    ADD_SS    = 0x10;  ADD_SR    = 0x11;  ADD_RR    = 0x12
    SUB_SS    = 0x13;  SUB_SR    = 0x14;  SUB_RR    = 0x15
    MUL_SS    = 0x16;  MUL_SR    = 0x17;  MUL_RR    = 0x18
    DIV_SS    = 0x19;  DIV_SR    = 0x1A;  DIV_RR    = 0x1B
    FDIV_SS   = 0x1C;  FDIV_SR   = 0x1D;  FDIV_RR   = 0x1E
    MOD_SS    = 0x1F;  MOD_SR    = 0x20;  MOD_RR    = 0x21
    POW_SS    = 0x22;  POW_SR    = 0x23;  POW_RR    = 0x24
    NEG_S     = 0x25;  NEG_R     = 0x26
    POS_S     = 0x27;  POS_R     = 0x28

    # ── Bitwise ───────────────────────────────────────────────────────────────
    BAND_SS   = 0x30;  BAND_SR   = 0x31
    BOR_SS    = 0x32;  BOR_SR    = 0x33
    BXOR_SS   = 0x34;  BXOR_SR   = 0x35
    BNOT_S    = 0x36;  BNOT_R    = 0x37
    LSHIFT_SS = 0x38;  RSHIFT_SS = 0x39

    # ── Logical ───────────────────────────────────────────────────────────────
    AND_SS = 0x40;  OR_SS  = 0x41;  NOT_S  = 0x42

    # ── Comparison ───────────────────────────────────────────────────────────
    EQ_SS  = 0x50;  NE_SS  = 0x51
    LT_SS  = 0x52;  LE_SS  = 0x53
    GT_SS  = 0x54;  GE_SS  = 0x55
    IS_SS  = 0x56;  IS_NOT_SS = 0x57
    IN_SS  = 0x58;  NOT_IN_SS = 0x59

    # ── Control flow ─────────────────────────────────────────────────────────
    JUMP         = 0x60   # abs offset (2 bytes)
    JUMP_IF_TRUE = 0x61   # pop, jump if truthy
    JUMP_IF_FALSE= 0x62   # pop, jump if falsy
    CALL_S       = 0x63   # func=pop(), args=meta
    CALL_R       = 0x64   # func=R[operand], args on stack
    RETURN_S     = 0x65   # return pop()
    RETURN_NONE  = 0x66   # return None
    YIELD_S      = 0x67
    RAISE_S      = 0x68
    SETUP_EXCEPT = 0x69   # handler offset
    END_EXCEPT   = 0x6A
    POP_EXCEPT   = 0x6B
    PUSH_EXCEPT  = 0x6C

    # ── Container builders ───────────────────────────────────────────────────
    BUILD_LIST   = 0x70
    BUILD_TUPLE  = 0x71
    BUILD_DICT   = 0x72
    BUILD_SET    = 0x73

    # ── Iteration ────────────────────────────────────────────────────────────
    GET_ITER   = 0x80
    FOR_ITER   = 0x81

    # ── Definitions ──────────────────────────────────────────────────────────
    MAKE_FUNC  = 0x90
    MAKE_CLASS = 0x91
    IMPORT     = 0x92
    IMPORT_FROM= 0x93
    IMPORT_STAR= 0x94

    # ── Join string ──────────────────────────────────────────────────────────
    JOIN_STR   = 0xA0
    FORMAT_VAL = 0xA1
    UNPACK_SEQ = 0xA2

    # ── Halt ─────────────────────────────────────────────────────────────────
    HALT       = 0xFF


# ─────────────────────────────────────────────────────────────────────────────
# Handler Pool – multiple equivalent implementations per op
# ─────────────────────────────────────────────────────────────────────────────

VMState = Any  # forward reference to the VM state object

def _make_add_pool():
    """Three semantically equivalent ADD_SS implementations."""
    def add_v0(vm):
        b = vm.stack_pop(); a = vm.stack_pop()
        vm.stack_push(a + b)

    def add_v1(vm):
        b = vm.stack_pop(); a = vm.stack_pop()
        # a + b ≡ -(-a - b)
        vm.stack_push(-((-a) - b))

    def add_v2(vm):
        b = vm.stack_pop(); a = vm.stack_pop()
        vm.stack_push(a.__add__(b) if hasattr(a, '__add__') else a + b)

    def add_v3(vm):
        b = vm.stack_pop(); a = vm.stack_pop()
        vm.stack_push(sum((a, b)))

    return [add_v0, add_v1, add_v2, add_v3]


def _make_sub_pool():
    def sub_v0(vm):
        b = vm.stack_pop(); a = vm.stack_pop(); vm.stack_push(a - b)
    def sub_v1(vm):
        b = vm.stack_pop(); a = vm.stack_pop(); vm.stack_push(a + (-b))
    def sub_v2(vm):
        b = vm.stack_pop(); a = vm.stack_pop(); vm.stack_push(-(b - a))
    return [sub_v0, sub_v1, sub_v2]


def _make_mul_pool():
    def mul_v0(vm):
        b = vm.stack_pop(); a = vm.stack_pop(); vm.stack_push(a * b)
    def mul_v1(vm):
        b = vm.stack_pop(); a = vm.stack_pop()
        # a * b  (using repeated add for small b won't work generically,
        # so just use operator overload path)
        vm.stack_push(a.__mul__(b) if hasattr(a, '__mul__') else a * b)
    return [mul_v0, mul_v1]


def _make_eq_pool():
    def eq_v0(vm):
        b = vm.stack_pop(); a = vm.stack_pop(); vm.stack_push(a == b)
    def eq_v1(vm):
        b = vm.stack_pop(); a = vm.stack_pop(); vm.stack_push(not (a != b))
    def eq_v2(vm):
        b = vm.stack_pop(); a = vm.stack_pop()
        vm.stack_push(a.__eq__(b) if hasattr(a, '__eq__') else a == b)
    return [eq_v0, eq_v1, eq_v2]


def _make_ne_pool():
    def ne_v0(vm):
        b = vm.stack_pop(); a = vm.stack_pop(); vm.stack_push(a != b)
    def ne_v1(vm):
        b = vm.stack_pop(); a = vm.stack_pop(); vm.stack_push(not (a == b))
    return [ne_v0, ne_v1]


def _make_not_pool():
    def not_v0(vm):
        a = vm.stack_pop(); vm.stack_push(not a)
    def not_v1(vm):
        a = vm.stack_pop(); vm.stack_push(True if not a else False)
    def not_v2(vm):
        a = vm.stack_pop(); vm.stack_push(a == False or a is None or a == 0 or a == "" or a == [] or a == {})
    return [not_v0, not_v1]


def _make_neg_pool():
    def neg_v0(vm):
        a = vm.stack_pop(); vm.stack_push(-a)
    def neg_v1(vm):
        a = vm.stack_pop(); vm.stack_push(0 - a)
    def neg_v2(vm):
        a = vm.stack_pop(); vm.stack_push(a.__neg__() if hasattr(a, '__neg__') else -a)
    return [neg_v0, neg_v1, neg_v2]


def _make_lt_pool():
    def lt_v0(vm):
        b = vm.stack_pop(); a = vm.stack_pop(); vm.stack_push(a < b)
    def lt_v1(vm):
        b = vm.stack_pop(); a = vm.stack_pop(); vm.stack_push(not (a >= b))
    return [lt_v0, lt_v1]


# Simple single-implementation ops (still in a list for uniform interface)
def _simple_handler(fn):
    return [fn]


def _make_handler_pool() -> Dict[int, List[Callable]]:
    """Build the complete handler pool keyed by LogicalOp value."""
    pool: Dict[int, List[Callable]] = {}

    def reg(op: LogicalOp, *handlers):
        pool[op.value] = list(handlers)

    # ── Polymorphic ops ──
    for h in _make_add_pool():   pool.setdefault(LogicalOp.ADD_SS.value, []).append(h)
    for h in _make_sub_pool():   pool.setdefault(LogicalOp.SUB_SS.value, []).append(h)
    for h in _make_mul_pool():   pool.setdefault(LogicalOp.MUL_SS.value, []).append(h)
    for h in _make_eq_pool():    pool.setdefault(LogicalOp.EQ_SS.value,  []).append(h)
    for h in _make_ne_pool():    pool.setdefault(LogicalOp.NE_SS.value,  []).append(h)
    for h in _make_not_pool():   pool.setdefault(LogicalOp.NOT_S.value,  []).append(h)
    for h in _make_neg_pool():   pool.setdefault(LogicalOp.NEG_S.value,  []).append(h)
    for h in _make_lt_pool():    pool.setdefault(LogicalOp.LT_SS.value,  []).append(h)

    # ── Single-impl ops (arithmetic) ──
    def div_ss(vm):  b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a/b)
    def fdiv_ss(vm): b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a//b)
    def mod_ss(vm):  b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a%b)
    def pow_ss(vm):  b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a**b)
    def mul_sr(vm):  r=vm.operand;a=vm.stack_pop();vm.stack_push(a*vm.regs[r])
    def add_sr(vm):  r=vm.operand;a=vm.stack_pop();vm.stack_push(a+vm.regs[r])
    def sub_sr(vm):  r=vm.operand;a=vm.stack_pop();vm.stack_push(a-vm.regs[r])
    def add_rr(vm):  r1,r2=vm.operand>>4,vm.operand&0xF;vm.regs[r1]=vm.regs[r1]+vm.regs[r2]
    def push_const(vm):vm.stack_push(vm.consts[vm.operand])
    def push_reg(vm):  vm.stack_push(vm.regs[vm.operand])
    def pop_reg(vm):   vm.regs[vm.operand]=vm.stack_pop()
    def pop_discard(vm):vm.stack_pop()
    def dup_top(vm):   v=vm.stack_top();vm.stack_push(v)
    def rot_two(vm):   a=vm.stack_pop();b=vm.stack_pop();vm.stack_push(a);vm.stack_push(b)
    def nop_h(vm):     pass
    def load_name(vm): vm.stack_push(vm.env_load(vm.names[vm.operand]))
    def store_name(vm):vm.env_store(vm.names[vm.operand], vm.stack_pop())
    def load_attr(vm): obj=vm.stack_pop();vm.stack_push(getattr(obj,vm.names[vm.operand]))
    def store_attr(vm):v=vm.stack_pop();setattr(vm.stack_pop(),vm.names[vm.operand],v)
    def load_index(vm):idx=vm.stack_pop();obj=vm.stack_pop();vm.stack_push(obj[idx])
    def store_index(vm):v=vm.stack_pop();idx=vm.stack_pop();obj=vm.stack_pop();obj[idx]=v
    def band_ss(vm): b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a&b)
    def bor_ss(vm):  b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a|b)
    def bxor_ss(vm): b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a^b)
    def bnot_s(vm):  vm.stack_push(~vm.stack_pop())
    def lshift_ss(vm):b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a<<b)
    def rshift_ss(vm):b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a>>b)
    def and_ss(vm):  b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a and b)
    def or_ss(vm):   b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a or b)
    def le_ss(vm):   b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a<=b)
    def gt_ss(vm):   b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a>b)
    def ge_ss(vm):   b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a>=b)
    def is_ss(vm):   b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a is b)
    def isnot_ss(vm):b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a is not b)
    def in_ss(vm):   b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a in b)
    def notin_ss(vm):b=vm.stack_pop();a=vm.stack_pop();vm.stack_push(a not in b)
    def pos_s(vm):   vm.stack_push(+vm.stack_pop())
    def build_list(vm):n=vm.operand;items=list(reversed([vm.stack_pop() for _ in range(n)]));vm.stack_push(items)
    def build_tuple(vm):n=vm.operand;items=tuple(reversed([vm.stack_pop() for _ in range(n)]));vm.stack_push(items)
    def build_dict(vm):
        n=vm.operand;d={}
        pairs=[(vm.stack_pop(),vm.stack_pop()) for _ in range(n)]
        for k,v in reversed(pairs):d[k]=v
        vm.stack_push(d)
    def build_set(vm):n=vm.operand;vm.stack_push(set(vm.stack_pop() for _ in range(n)))
    def get_iter(vm): vm.stack_push(iter(vm.stack_pop()))
    def for_iter(vm): # handled specially in run loop
        it=vm.stack_top()
        try: vm.stack_push(next(it))
        except StopIteration: vm.pc=vm.operand  # jump to end
    def call_s(vm):
        n_args=vm.operand;args=list(reversed([vm.stack_pop() for _ in range(n_args)]))
        func=vm.stack_pop();vm.stack_push(func(*args))
    def call_r(vm):
        n_args=vm.operand>>4;reg=vm.operand&0xF
        args=list(reversed([vm.stack_pop() for _ in range(n_args)]))
        vm.stack_push(vm.regs[reg](*args))
    def return_s(vm):  vm.return_val=vm.stack_pop();vm.running=False
    def return_none(vm):vm.return_val=None;vm.running=False
    def yield_s(vm):   vm.yield_val=vm.stack_pop();vm.yielded=True
    def raise_s(vm):   raise vm.stack_pop()
    def jump(vm):      vm.pc=vm.operand
    def jump_true(vm): v=vm.stack_pop();vm.pc=vm.operand if v else vm.pc
    def jump_false(vm):v=vm.stack_pop();vm.pc=vm.operand if not v else vm.pc
    def setup_except(vm):vm.except_stack.append(vm.operand)
    def end_except(vm): 
        if vm.except_stack: vm.except_stack.pop()
    def pop_except(vm): vm.current_exc=None
    def push_except(vm):vm.stack_push(vm.current_exc)
    def make_func(vm):  vm.stack_push(vm.make_function(vm.operand))
    def make_cls(vm):   vm.stack_push(vm.make_class(vm.operand))
    def import_h(vm):   vm.stack_push(__import__(vm.names[vm.operand]))
    def import_from(vm):name=vm.names[vm.operand];vm.stack_push(getattr(vm.stack_top(),name))
    def import_star(vm):
        mod=vm.stack_pop()
        names=getattr(mod,'__all__',None) or [n for n in dir(mod) if not n.startswith('_')]
        for n in names: vm.env_store(n, getattr(mod, n))
    def join_str(vm): n=vm.operand;parts=list(reversed([vm.stack_pop() for _ in range(n)]));vm.stack_push(''.join(str(p) for p in parts))
    def unpack_seq(vm):n=vm.operand;seq=vm.stack_pop();items=list(seq);[vm.stack_push(items[i]) for i in range(n-1,-1,-1)]
    def delete_name(vm):vm.env_delete(vm.names[vm.operand])
    def halt_h(vm):    vm.running=False

    singles = {
        LogicalOp.DIV_SS:    div_ss,   LogicalOp.FDIV_SS:  fdiv_ss,
        LogicalOp.MOD_SS:    mod_ss,   LogicalOp.POW_SS:   pow_ss,
        LogicalOp.ADD_SR:    add_sr,   LogicalOp.SUB_SR:   sub_sr,
        LogicalOp.MUL_SR:    mul_sr,   LogicalOp.ADD_RR:   add_rr,
        LogicalOp.POS_S:     pos_s,
        LogicalOp.PUSH_CONST: push_const, LogicalOp.PUSH_REG: push_reg,
        LogicalOp.POP_REG:   pop_reg,  LogicalOp.POP_DISCARD: pop_discard,
        LogicalOp.DUP_TOP:   dup_top,  LogicalOp.ROT_TWO:  rot_two,
        LogicalOp.NOP:       nop_h,
        LogicalOp.LOAD_NAME: load_name, LogicalOp.STORE_NAME: store_name,
        LogicalOp.LOAD_ATTR: load_attr, LogicalOp.STORE_ATTR: store_attr,
        LogicalOp.LOAD_INDEX: load_index, LogicalOp.STORE_INDEX: store_index,
        LogicalOp.DELETE_NAME: delete_name,
        LogicalOp.BAND_SS:   band_ss,  LogicalOp.BOR_SS:   bor_ss,
        LogicalOp.BXOR_SS:   bxor_ss, LogicalOp.BNOT_S:   bnot_s,
        LogicalOp.LSHIFT_SS: lshift_ss, LogicalOp.RSHIFT_SS: rshift_ss,
        LogicalOp.AND_SS:    and_ss,   LogicalOp.OR_SS:    or_ss,
        LogicalOp.LE_SS:     le_ss,    LogicalOp.GT_SS:    gt_ss,
        LogicalOp.GE_SS:     ge_ss,    LogicalOp.IS_SS:    is_ss,
        LogicalOp.IS_NOT_SS: isnot_ss, LogicalOp.IN_SS:    in_ss,
        LogicalOp.NOT_IN_SS: notin_ss,
        LogicalOp.BUILD_LIST: build_list, LogicalOp.BUILD_TUPLE: build_tuple,
        LogicalOp.BUILD_DICT: build_dict, LogicalOp.BUILD_SET:  build_set,
        LogicalOp.GET_ITER:  get_iter, LogicalOp.FOR_ITER:  for_iter,
        LogicalOp.CALL_S:    call_s,   LogicalOp.CALL_R:    call_r,
        LogicalOp.RETURN_S:  return_s, LogicalOp.RETURN_NONE: return_none,
        LogicalOp.YIELD_S:   yield_s,  LogicalOp.RAISE_S:   raise_s,
        LogicalOp.JUMP:      jump,     LogicalOp.JUMP_IF_TRUE: jump_true,
        LogicalOp.JUMP_IF_FALSE: jump_false,
        LogicalOp.SETUP_EXCEPT: setup_except, LogicalOp.END_EXCEPT: end_except,
        LogicalOp.POP_EXCEPT: pop_except, LogicalOp.PUSH_EXCEPT: push_except,
        LogicalOp.MAKE_FUNC: make_func, LogicalOp.MAKE_CLASS: make_cls,
        LogicalOp.IMPORT:    import_h, LogicalOp.IMPORT_FROM: import_from,
        LogicalOp.IMPORT_STAR: import_star,
        LogicalOp.JOIN_STR:  join_str, LogicalOp.UNPACK_SEQ: unpack_seq,
        LogicalOp.HALT:      halt_h,
    }
    for op, fn in singles.items():
        pool.setdefault(op.value, []).append(fn)

    return pool


HANDLER_POOL: Dict[int, List[Callable]] = _make_handler_pool()


# ─────────────────────────────────────────────────────────────────────────────
# Runtime Dispatch Table – built fresh every VM startup
# ─────────────────────────────────────────────────────────────────────────────

class RuntimeDispatchTable:
    """
    Built once at VM startup from a runtime-derived seed.
    Provides:
      • dispatch_table[logical_op_value] → selected handler function
      • physical_to_logical[physical_byte] → logical_op_value
      • logical_to_physical[logical_op_value] → physical_byte
      • aslr_xor_pad(length) → bytes pad for in-memory XOR
    """

    def __init__(self, seed: Optional[int] = None):
        self._seed = seed if seed is not None else self._derive_runtime_seed()
        self._rng  = random.Random(self._seed)

        # Step 1: Select one handler per logical op from its pool
        self.dispatch_table: Dict[int, Callable] = {}
        for op_val, handlers in HANDLER_POOL.items():
            self.dispatch_table[op_val] = self._rng.choice(handlers)

        # Step 2: Build physical ↔ logical byte mapping (opcode shuffling)
        logical_vals = list(HANDLER_POOL.keys())
        available    = list(range(256))
        self._rng.shuffle(available)
        self.logical_to_physical: Dict[int, int] = {}
        self.physical_to_logical: Dict[int, int] = {}
        for i, lv in enumerate(logical_vals):
            pv = available[i]
            self.logical_to_physical[lv] = pv
            self.physical_to_logical[pv] = lv

        # Fill unmapped physical bytes with NOP handlers (decoys)
        mapped_phys = set(self.physical_to_logical.keys())
        for pv in range(256):
            if pv not in mapped_phys:
                self.physical_to_logical[pv] = LogicalOp.NOP.value

        # Step 3: ASLR-based XOR key (different every process run)
        self._aslr_key = self._compute_aslr_key()

    # ── seed derivation ───────────────────────────────────────────────────────

    @staticmethod
    def _derive_runtime_seed() -> int:
        """
        Derives an unpredictable runtime seed from:
        - ASLR: id() of freshly allocated objects
        - OS entropy: os.urandom
        - Process timing: time.perf_counter_ns
        """
        obj1 = object(); obj2 = object(); obj3 = []
        aslr = (id(obj1) ^ id(obj2) ^ id(obj3)) & 0xFFFFFFFFFFFFFFFF
        t    = time.perf_counter_ns() & 0xFFFFFFFF
        rnd  = int.from_bytes(os.urandom(8), 'little')
        raw  = struct.pack('<QQQ', aslr, t, rnd)
        h    = hashlib.sha256(raw).digest()
        return int.from_bytes(h[:8], 'little')

    @staticmethod
    def _compute_aslr_key() -> int:
        """Single-byte ASLR-derived XOR key."""
        obj = object()
        return (id(obj) >> 4) & 0xFF

    # ── XOR pad generation ────────────────────────────────────────────────────

    def aslr_xor_pad(self, length: int) -> bytes:
        """
        Generates a length-byte XOR pad using ASLR key + PRNG.
        Used to scramble bytecode in memory.
        """
        rng = random.Random(self._aslr_key ^ self._seed)
        return bytes(rng.randint(0, 255) for _ in range(length))

    def xor_bytecode(self, data: bytes) -> bytes:
        """XOR-scramble bytecode for in-memory storage."""
        pad = self.aslr_xor_pad(len(data))
        return bytes(a ^ b for a, b in zip(data, pad))

    def unxor_bytecode(self, data: bytes) -> bytes:
        """Reverse the XOR (same operation)."""
        return self.xor_bytecode(data)

    # ── lookup helpers ────────────────────────────────────────────────────────

    def decode(self, physical_byte: int) -> Callable:
        """physical_byte → handler, O(1)."""
        lv = self.physical_to_logical.get(physical_byte, LogicalOp.NOP.value)
        return self.dispatch_table.get(lv, self.dispatch_table[LogicalOp.NOP.value])

    def encode_op(self, logical_op: LogicalOp) -> int:
        """Logical op → physical byte for bytecode emission."""
        return self.logical_to_physical.get(logical_op.value, 0)

    # ── serialise for loader injection ───────────────────────────────────────

    def serialise_seed(self) -> bytes:
        """
        Returns the 8-byte seed so the runtime loader can reconstruct
        the same dispatch table without storing it in plaintext.
        The seed itself is stored encrypted (AES-GCM) in the payload header.
        """
        return struct.pack('<Q', self._seed)

    # ── debug ─────────────────────────────────────────────────────────────────

    def debug_info(self) -> str:
        lines = [f"RuntimeDispatchTable(seed=0x{self._seed:016x})"]
        lines.append(f"  ASLR XOR key : 0x{self._aslr_key:02x}")
        lines.append(f"  Mapped ops   : {len(self.logical_to_physical)}")
        sample = list(HANDLER_POOL.keys())[:5]
        for lv in sample:
            pv = self.logical_to_physical.get(lv, -1)
            h  = self.dispatch_table.get(lv, None)
            lines.append(f"  LogOp 0x{lv:02x} → PhysByte 0x{pv:02x} "
                          f"→ handler {h.__name__ if h else '?'}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Factory (called by stage2 compiler and VM loader)
# ─────────────────────────────────────────────────────────────────────────────

def build_runtime_dispatch(seed: Optional[int] = None) -> RuntimeDispatchTable:
    """Build a fresh RuntimeDispatchTable. Called at VM startup."""
    return RuntimeDispatchTable(seed=seed)


# ─── self-test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    dt1 = build_runtime_dispatch()
    dt2 = build_runtime_dispatch()
    print(dt1.debug_info())
    print()
    print(dt2.debug_info())
    print()
    # Verify different seeds → different physical bytes for ADD_SS
    p1 = dt1.encode_op(LogicalOp.ADD_SS)
    p2 = dt2.encode_op(LogicalOp.ADD_SS)
    print(f"ADD_SS physical byte run1=0x{p1:02x}  run2=0x{p2:02x}  differ={p1!=p2}")
    # Verify XOR pad differs
    b = b"Hello, World!"
    x1 = dt1.xor_bytecode(b); x2 = dt2.xor_bytecode(b)
    print(f"XOR differ: {x1 != x2}")
