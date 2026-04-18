"""
Common IR (Intermediate Representation) data structures.
Three-Address Code (TAC) format: (op, dest, src1, src2, meta)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum


class IROpcode(str, Enum):
    # ── Data movement ─────────────────────────────
    ASSIGN      = "ASSIGN"       # dest = src1
    LOAD_NAME   = "LOAD_NAME"    # dest = env[src1]
    STORE_NAME  = "STORE_NAME"   # env[dest] = src1
    LOAD_CONST  = "LOAD_CONST"   # dest = meta['value']
    LOAD_ATTR   = "LOAD_ATTR"    # dest = src1.meta['attr']
    STORE_ATTR  = "STORE_ATTR"   # src1.meta['attr'] = src2
    LOAD_INDEX  = "LOAD_INDEX"   # dest = src1[src2]
    STORE_INDEX = "STORE_INDEX"  # src1[src2] = meta['value']
    DELETE_NAME = "DELETE_NAME"  # del env[dest]
    GLOBAL_DECL    = "GLOBAL_DECL"
    NONLOCAL_DECL  = "NONLOCAL_DECL"

    # ── Arithmetic ────────────────────────────────
    ADD       = "ADD"
    SUB       = "SUB"
    MUL       = "MUL"
    DIV       = "DIV"
    FLOOR_DIV = "FLOOR_DIV"
    MOD       = "MOD"
    POW       = "POW"
    MATMUL    = "MATMUL"
    NEG       = "NEG"            # dest = -src1
    POS       = "POS"            # dest = +src1

    # ── Bitwise ───────────────────────────────────
    BAND   = "BAND"
    BOR    = "BOR"
    BXOR   = "BXOR"
    BNOT   = "BNOT"
    LSHIFT = "LSHIFT"
    RSHIFT = "RSHIFT"

    # ── Logical ───────────────────────────────────
    AND = "AND"
    OR  = "OR"
    NOT = "NOT"

    # ── Comparison ───────────────────────────────
    EQ     = "EQ"
    NE     = "NE"
    LT     = "LT"
    LE     = "LE"
    GT     = "GT"
    GE     = "GE"
    IS     = "IS"
    IS_NOT = "IS_NOT"
    IN     = "IN"
    NOT_IN = "NOT_IN"

    # ── Control flow ─────────────────────────────
    LABEL      = "LABEL"        # label anchor (meta['name'])
    JUMP       = "JUMP"         # goto meta['target']
    CJUMP      = "CJUMP"        # if src1 goto meta['true'] else meta['false']
    CALL       = "CALL"         # dest = src1(*meta['args'], **meta['kwargs'])
    RETURN     = "RETURN"       # return src1
    YIELD      = "YIELD"        # dest = yield src1
    YIELD_FROM = "YIELD_FROM"   # dest = yield from src1
    RAISE      = "RAISE"        # raise src1 [from src2]
    ASSERT     = "ASSERT"       # assert src1, src2

    # ── Containers ───────────────────────────────
    BUILD_LIST  = "BUILD_LIST"   # dest = [meta['items']]
    BUILD_TUPLE = "BUILD_TUPLE"
    BUILD_DICT  = "BUILD_DICT"   # meta['keys'], meta['values']
    BUILD_SET   = "BUILD_SET"
    BUILD_SLICE = "BUILD_SLICE"  # dest = slice(src1, src2, meta['step'])

    # ── Iteration ────────────────────────────────
    GET_ITER = "GET_ITER"        # dest = iter(src1)
    FOR_ITER = "FOR_ITER"        # dest = next(src1) or jump meta['end']

    # ── Unpacking ────────────────────────────────
    UNPACK_SEQ = "UNPACK_SEQ"    # meta['targets'] = src1

    # ── Exception ────────────────────────────────
    SETUP_EXCEPT  = "SETUP_EXCEPT"   # meta['handler']
    SETUP_FINALLY = "SETUP_FINALLY"
    END_EXCEPT    = "END_EXCEPT"
    POP_EXCEPT    = "POP_EXCEPT"
    PUSH_EXCEPT   = "PUSH_EXCEPT"    # dest = current exception tuple
    WITH_ENTER    = "WITH_ENTER"     # dest = src1.__enter__()
    WITH_EXIT     = "WITH_EXIT"      # src1.__exit__(...)

    # ── Definitions ──────────────────────────────
    MAKE_FUNCTION = "MAKE_FUNCTION"  # dest = closure(meta['name'], meta['code'])
    MAKE_CLASS    = "MAKE_CLASS"     # dest = type(name, bases, body)

    # ── Imports ──────────────────────────────────
    IMPORT_NAME = "IMPORT_NAME"   # dest = __import__(meta['module'])
    IMPORT_FROM = "IMPORT_FROM"   # dest = getattr(src1, meta['name'])
    IMPORT_STAR = "IMPORT_STAR"   # from src1 import *

    # ── Format strings ───────────────────────────
    FORMAT_VALUE = "FORMAT_VALUE"
    JOIN_STR     = "JOIN_STR"

    # ── SSA / misc ───────────────────────────────
    PHI = "PHI"     # dest = phi(meta['sources'])  [SSA]
    NOP = "NOP"


@dataclass
class IRInstruction:
    op:   IROpcode
    dest: Optional[str]      = None
    src1: Optional[str]      = None
    src2: Optional[str]      = None
    meta: Dict[str, Any]     = field(default_factory=dict)
    line_no: int             = 0

    def __repr__(self) -> str:
        lhs  = f"{self.dest} = " if self.dest else ""
        srcs = " ".join(filter(None, [self.src1, self.src2]))
        m    = f" {self.meta}" if self.meta else ""
        return f"[{self.op.value}] {lhs}{srcs}{m}".strip()

    def clone(self) -> IRInstruction:
        import copy
        return IRInstruction(
            op=self.op, dest=self.dest, src1=self.src1, src2=self.src2,
            meta=copy.deepcopy(self.meta), line_no=self.line_no
        )


@dataclass
class BasicBlock:
    label:        str
    instructions: List[IRInstruction] = field(default_factory=list)
    predecessors: List[str]           = field(default_factory=list)
    successors:   List[str]           = field(default_factory=list)
    # hotness weight (filled by profiler)
    weight: float = 1.0

    def add(self, instr: IRInstruction):
        self.instructions.append(instr)

    def terminator(self) -> Optional[IRInstruction]:
        for instr in reversed(self.instructions):
            if instr.op in (IROpcode.JUMP, IROpcode.CJUMP,
                            IROpcode.RETURN, IROpcode.RAISE):
                return instr
        return None


@dataclass
class CFG:
    blocks: Dict[str, BasicBlock] = field(default_factory=dict)
    entry:  str = ""
    exit_:  str = ""

    def add_block(self, block: BasicBlock):
        self.blocks[block.label] = block

    def add_edge(self, frm: str, to: str):
        b_frm = self.blocks.get(frm)
        b_to  = self.blocks.get(to)
        if b_frm and to not in b_frm.successors:
            b_frm.successors.append(to)
        if b_to and frm not in b_to.predecessors:
            b_to.predecessors.append(frm)

    def all_instructions(self) -> List[IRInstruction]:
        out = []
        for lbl in self._topo_order():
            out.extend(self.blocks[lbl].instructions)
        return out

    def _topo_order(self) -> List[str]:
        visited, order = set(), []
        def dfs(lbl):
            if lbl in visited or lbl not in self.blocks:
                return
            visited.add(lbl)
            for s in self.blocks[lbl].successors:
                dfs(s)
            order.append(lbl)
        dfs(self.entry)
        return list(reversed(order))


@dataclass
class IRFunction:
    name:        str
    args:        List[str]           = field(default_factory=list)
    varargs:     Optional[str]       = None
    kwargs:      Optional[str]       = None
    defaults:    Dict[str, Any]      = field(default_factory=dict)
    instructions: List[IRInstruction] = field(default_factory=list)
    cfg:         Optional[CFG]       = None
    locals_:     List[str]           = field(default_factory=list)
    globals_used: List[str]          = field(default_factory=list)
    constants:   Dict[str, Any]      = field(default_factory=dict)
    is_generator: bool               = False
    is_async:     bool               = False
    decorators:   List[str]          = field(default_factory=list)
    nested:       Dict[str, 'IRFunction'] = field(default_factory=dict)

    def flat_instructions(self) -> List[IRInstruction]:
        if self.cfg:
            return self.cfg.all_instructions()
        return self.instructions


@dataclass
class IRClass:
    name:    str
    bases:   List[str]              = field(default_factory=list)
    methods: Dict[str, IRFunction]  = field(default_factory=dict)
    attrs:   Dict[str, Any]         = field(default_factory=dict)
    decorators: List[str]           = field(default_factory=list)


@dataclass
class IRModule:
    name:         str
    source_file:  str                      = ""
    functions:    Dict[str, IRFunction]    = field(default_factory=dict)
    classes:      Dict[str, IRClass]       = field(default_factory=dict)
    module_instrs: List[IRInstruction]     = field(default_factory=list)
    constants:    Dict[str, Any]           = field(default_factory=dict)
    imports:      List[str]                = field(default_factory=list)
    # profiler annotations
    hot_functions: List[str]               = field(default_factory=list)

    def all_functions(self) -> Dict[str, IRFunction]:
        """Flatten nested functions too."""
        result = dict(self.functions)
        def collect(fn: IRFunction, prefix: str):
            for name, nested in fn.nested.items():
                key = f"{prefix}.{name}"
                result[key] = nested
                collect(nested, key)
        for name, fn in self.functions.items():
            collect(fn, name)
        return result
