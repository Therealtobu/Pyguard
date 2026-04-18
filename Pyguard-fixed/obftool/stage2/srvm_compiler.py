"""
Module 2.1 – SR-VM Compiler
Compiles IR_main (TAC instructions) to SR-VM bytecode.

Bytecode format per instruction:
  [physical_opcode: u8] [operand: u16 LE]   → 3 bytes per instruction
  (some ops don't use operand; stored as 0)

Operand meaning depends on opcode:
  PUSH_CONST   → index into const_table
  PUSH_REG     → register index (0-15)
  POP_REG      → register index
  LOAD_NAME    → index into name_table
  STORE_NAME   → index into name_table
  LOAD_ATTR    → index into name_table
  JUMP*        → absolute byte offset
  CALL_S       → n_args
  BUILD_*      → n_items
  FOR_ITER     → offset of end label
  SETUP_EXCEPT → offset of handler

The compiler uses a BUILD-TIME dispatch table to know which physical
byte to emit for each logical op (since this is keyed by the runtime
seed stored in the payload header).
"""

from __future__ import annotations
import struct
from typing import List, Dict, Any, Optional, Tuple

from common.ir import (
    IROpcode, IRInstruction, IRFunction, IRModule
)
from stage2.opcode_poly_gen import LogicalOp, RuntimeDispatchTable, build_runtime_dispatch


# ─────────────────────────────────────────────────────────────────────────────
# SR-VM Bytecode
# ─────────────────────────────────────────────────────────────────────────────

INSTR_SIZE = 3  # bytes per instruction: 1 opcode + 2 operand


class Bytecode:
    """
    Holds the compiled bytecode for one function.
    """

    def __init__(self):
        self.raw:        bytearray          = bytearray()
        self.const_table: List[Any]         = []
        self.name_table:  List[str]         = []
        self.label_offsets: Dict[str, int]  = {}  # label → byte offset
        self._patch_list: List[Tuple[int, str]] = []  # (patch_pos, label)

    # ── const / name tables ──────────────────────────────────────────────────

    def const_idx(self, value: Any) -> int:
        if value in self.const_table:
            return self.const_table.index(value)
        self.const_table.append(value)
        return len(self.const_table) - 1

    def name_idx(self, name: str) -> int:
        if name in self.name_table:
            return self.name_table.index(name)
        self.name_table.append(name)
        return len(self.name_table) - 1

    # ── emission ─────────────────────────────────────────────────────────────

    def emit(self, phys_op: int, operand: int = 0):
        self.raw.append(phys_op & 0xFF)
        self.raw.extend(struct.pack('<H', operand & 0xFFFF))

    def current_offset(self) -> int:
        return len(self.raw)

    def mark_label(self, name: str):
        self.label_offsets[name] = self.current_offset()

    def emit_jump(self, phys_op: int, target_label: str):
        patch_pos = self.current_offset() + 1  # operand field position
        self._patch_list.append((patch_pos, target_label))
        self.emit(phys_op, 0)  # placeholder

    def patch_jumps(self):
        for pos, label in self._patch_list:
            offset = self.label_offsets.get(label, 0)
            struct.pack_into('<H', self.raw, pos, offset & 0xFFFF)

    def bytes(self) -> bytes:
        return bytes(self.raw)


# ─────────────────────────────────────────────────────────────────────────────
# SR-VM Compiler
# ─────────────────────────────────────────────────────────────────────────────

class SRVMCompiler:
    """
    Compiles a flat list of IRInstructions to SR-VM bytecode.

    Register allocation:
      - $tN temporaries → allocated greedily to R0-R15, spill to stack
      - Named variables  → always via LOAD_NAME / STORE_NAME (env dict)
    """

    N_REGS = 16

    def __init__(self, dispatch: RuntimeDispatchTable):
        self._dispatch = dispatch
        self._reg_alloc: Dict[str, int] = {}  # tmp → reg index
        self._reg_free:  List[int]      = list(range(self.N_REGS))

    def compile_module(self, module: IRModule) -> Dict[str, Bytecode]:
        results = {}
        for name, fn in module.functions.items():
            bc = self._compile_function(fn)
            results[name] = bc
        for cls in module.classes.values():
            for mname, method in cls.methods.items():
                bc = self._compile_function(method)
                results[f"{cls.name}.{mname}"] = bc
        # Module body
        bc = self._compile_instrs(module.module_instrs)
        results["<module>"] = bc
        return results

    def _compile_function(self, fn: IRFunction) -> Bytecode:
        self._reg_alloc = {}
        self._reg_free  = list(range(self.N_REGS))
        return self._compile_instrs(fn.instructions)

    def _compile_instrs(self, instrs: List[IRInstruction]) -> Bytecode:
        bc = Bytecode()

        for instr in instrs:
            self._compile_instr(instr, bc)

        # Emit HALT at end
        bc.emit(self._op(LogicalOp.HALT))

        # Back-patch jump targets
        bc.patch_jumps()
        return bc

    def _compile_instr(self, instr: IRInstruction, bc: Bytecode):
        op = instr.op

        # ── LABEL ────────────────────────────────────────────────────────────
        if op is IROpcode.LABEL:
            bc.mark_label(instr.meta.get("name", ""))
            return

        # ── LOAD_CONST ───────────────────────────────────────────────────────
        elif op is IROpcode.LOAD_CONST:
            val = instr.meta.get("value")
            idx = bc.const_idx(val)
            self._emit_to_dest(instr.dest, LogicalOp.PUSH_CONST, idx, bc)

        # ── LOAD_NAME ────────────────────────────────────────────────────────
        elif op is IROpcode.LOAD_NAME:
            name = instr.src1 or instr.dest
            idx  = bc.name_idx(name)
            self._emit_to_dest(instr.dest, LogicalOp.LOAD_NAME, idx, bc)

        # ── STORE_NAME ───────────────────────────────────────────────────────
        elif op is IROpcode.STORE_NAME:
            self._push_src(instr.src1, bc)
            idx = bc.name_idx(instr.dest)
            bc.emit(self._op(LogicalOp.STORE_NAME), idx)
            self._free_tmp(instr.src1)

        # ── ASSIGN ───────────────────────────────────────────────────────────
        elif op is IROpcode.ASSIGN:
            self._push_src(instr.src1, bc)
            reg = self._alloc_reg(instr.dest)
            if reg is not None:
                bc.emit(self._op(LogicalOp.POP_REG), reg)
            else:
                idx = bc.name_idx(instr.dest)
                bc.emit(self._op(LogicalOp.STORE_NAME), idx)

        # ── Arithmetic / bitwise / logical / comparison ───────────────────────
        elif op in _IR_TO_SRVM:
            lop = _IR_TO_SRVM[op]
            self._push_src(instr.src1, bc)
            self._push_src(instr.src2, bc)
            bc.emit(self._op(lop))
            self._pop_to_dest(instr.dest, bc)

        # ── NEG / NOT / POS / BNOT (unary) ───────────────────────────────────
        elif op in _UNARY_MAP:
            lop = _UNARY_MAP[op]
            self._push_src(instr.src1, bc)
            bc.emit(self._op(lop))
            self._pop_to_dest(instr.dest, bc)

        # ── LOAD_ATTR ────────────────────────────────────────────────────────
        elif op is IROpcode.LOAD_ATTR:
            self._push_src(instr.src1, bc)
            idx = bc.name_idx(instr.meta.get("attr", ""))
            bc.emit(self._op(LogicalOp.LOAD_ATTR), idx)
            self._pop_to_dest(instr.dest, bc)

        # ── STORE_ATTR ───────────────────────────────────────────────────────
        elif op is IROpcode.STORE_ATTR:
            self._push_src(instr.src1, bc)
            self._push_src(instr.src2, bc)
            idx = bc.name_idx(instr.meta.get("attr", ""))
            bc.emit(self._op(LogicalOp.STORE_ATTR), idx)

        # ── LOAD_INDEX ───────────────────────────────────────────────────────
        elif op is IROpcode.LOAD_INDEX:
            self._push_src(instr.src1, bc)
            self._push_src(instr.src2, bc)
            bc.emit(self._op(LogicalOp.LOAD_INDEX))
            self._pop_to_dest(instr.dest, bc)

        # ── STORE_INDEX ──────────────────────────────────────────────────────
        elif op is IROpcode.STORE_INDEX:
            self._push_src(instr.src1, bc)
            self._push_src(instr.src2, bc)
            val = instr.meta.get("value")
            if val:
                self._push_src(val, bc)
            bc.emit(self._op(LogicalOp.STORE_INDEX))

        # ── JUMP ─────────────────────────────────────────────────────────────
        elif op is IROpcode.JUMP:
            target = instr.meta.get("target", "")
            bc.emit_jump(self._op(LogicalOp.JUMP), target)

        # ── CJUMP ────────────────────────────────────────────────────────────
        elif op is IROpcode.CJUMP:
            self._push_src(instr.src1, bc)
            false_tgt = instr.meta.get("false", "")
            bc.emit_jump(self._op(LogicalOp.JUMP_IF_FALSE), false_tgt)
            # fall through to true branch (or emit separate jump)
            true_tgt = instr.meta.get("true", "")
            if true_tgt and true_tgt != "$fall":
                bc.emit_jump(self._op(LogicalOp.JUMP), true_tgt)

        # ── CALL ─────────────────────────────────────────────────────────────
        elif op is IROpcode.CALL:
            func = instr.src1
            args = instr.meta.get("args", [])
            # Push all args first, then func
            for arg in args:
                if isinstance(arg, tuple):
                    self._push_src(arg[1], bc)
                else:
                    self._push_src(arg, bc)
            self._push_src(func, bc)
            n_args = len(args)
            bc.emit(self._op(LogicalOp.CALL_S), n_args)
            self._pop_to_dest(instr.dest, bc)

        # ── RETURN ───────────────────────────────────────────────────────────
        elif op is IROpcode.RETURN:
            if instr.src1:
                self._push_src(instr.src1, bc)
                bc.emit(self._op(LogicalOp.RETURN_S))
            else:
                bc.emit(self._op(LogicalOp.RETURN_NONE))

        # ── RAISE ────────────────────────────────────────────────────────────
        elif op is IROpcode.RAISE:
            if instr.src1:
                self._push_src(instr.src1, bc)
            bc.emit(self._op(LogicalOp.RAISE_S))

        # ── BUILD_LIST / TUPLE / DICT / SET ──────────────────────────────────
        elif op is IROpcode.BUILD_LIST:
            items = instr.meta.get("items", [])
            for item in items:
                self._push_src(item, bc)
            bc.emit(self._op(LogicalOp.BUILD_LIST), len(items))
            self._pop_to_dest(instr.dest, bc)

        elif op is IROpcode.BUILD_TUPLE:
            items = instr.meta.get("items", [])
            for item in items:
                self._push_src(item, bc)
            bc.emit(self._op(LogicalOp.BUILD_TUPLE), len(items))
            self._pop_to_dest(instr.dest, bc)

        elif op is IROpcode.BUILD_DICT:
            keys   = instr.meta.get("keys", [])
            values = instr.meta.get("values", [])
            for k, v in zip(keys, values):
                if k: self._push_src(k, bc)
                self._push_src(v, bc)
            bc.emit(self._op(LogicalOp.BUILD_DICT), len(keys))
            self._pop_to_dest(instr.dest, bc)

        elif op is IROpcode.BUILD_SET:
            items = instr.meta.get("items", [])
            for item in items:
                self._push_src(item, bc)
            bc.emit(self._op(LogicalOp.BUILD_SET), len(items))
            self._pop_to_dest(instr.dest, bc)

        # ── GET_ITER / FOR_ITER ───────────────────────────────────────────────
        elif op is IROpcode.GET_ITER:
            self._push_src(instr.src1, bc)
            bc.emit(self._op(LogicalOp.GET_ITER))
            self._pop_to_dest(instr.dest, bc)

        elif op is IROpcode.FOR_ITER:
            self._push_src(instr.src1, bc)
            end_lbl = instr.meta.get("end", "")
            bc.emit_jump(self._op(LogicalOp.FOR_ITER), end_lbl)
            self._pop_to_dest(instr.dest, bc)

        # ── SETUP_EXCEPT / END_EXCEPT / POP_EXCEPT / PUSH_EXCEPT ────────────
        elif op is IROpcode.SETUP_EXCEPT:
            handler = instr.meta.get("handler", "")
            bc.emit_jump(self._op(LogicalOp.SETUP_EXCEPT), handler)

        elif op is IROpcode.END_EXCEPT:
            bc.emit(self._op(LogicalOp.END_EXCEPT))

        elif op is IROpcode.POP_EXCEPT:
            bc.emit(self._op(LogicalOp.POP_EXCEPT))

        elif op is IROpcode.PUSH_EXCEPT:
            bc.emit(self._op(LogicalOp.PUSH_EXCEPT))
            self._pop_to_dest(instr.dest, bc)

        # ── IMPORT ───────────────────────────────────────────────────────────
        elif op is IROpcode.IMPORT_NAME:
            idx = bc.name_idx(instr.meta.get("module", ""))
            bc.emit(self._op(LogicalOp.IMPORT), idx)
            self._pop_to_dest(instr.dest, bc)

        elif op is IROpcode.IMPORT_FROM:
            self._push_src(instr.src1, bc)
            idx = bc.name_idx(instr.meta.get("name", ""))
            bc.emit(self._op(LogicalOp.IMPORT_FROM), idx)
            self._pop_to_dest(instr.dest, bc)

        elif op is IROpcode.IMPORT_STAR:
            self._push_src(instr.src1, bc)
            bc.emit(self._op(LogicalOp.IMPORT_STAR))

        # ── UNPACK_SEQ ───────────────────────────────────────────────────────
        elif op is IROpcode.UNPACK_SEQ:
            self._push_src(instr.src1, bc)
            n = instr.meta.get("n", 0)
            bc.emit(self._op(LogicalOp.UNPACK_SEQ), n)
            # Store each target
            for tgt in reversed(instr.meta.get("targets", [])):
                idx = bc.name_idx(tgt)
                bc.emit(self._op(LogicalOp.STORE_NAME), idx)

        # ── MAKE_FUNCTION / MAKE_CLASS ────────────────────────────────────────
        elif op is IROpcode.MAKE_FUNCTION:
            idx = bc.const_idx(instr.meta.get("name", ""))
            bc.emit(self._op(LogicalOp.MAKE_FUNC), idx)
            self._pop_to_dest(instr.dest, bc)

        elif op is IROpcode.MAKE_CLASS:
            idx = bc.const_idx(instr.meta.get("name", ""))
            bc.emit(self._op(LogicalOp.MAKE_CLASS), idx)
            self._pop_to_dest(instr.dest, bc)

        # ── YIELD ────────────────────────────────────────────────────────────
        elif op is IROpcode.YIELD:
            if instr.src1:
                self._push_src(instr.src1, bc)
            bc.emit(self._op(LogicalOp.YIELD_S))
            self._pop_to_dest(instr.dest, bc)

        # ── GLOBAL_DECL / NONLOCAL_DECL / DELETE_NAME / NOP ─────────────────
        elif op is IROpcode.DELETE_NAME:
            idx = bc.name_idx(instr.dest or "")
            bc.emit(self._op(LogicalOp.DELETE_NAME), idx)

        elif op is IROpcode.JOIN_STR:
            parts = instr.meta.get("parts", [])
            for p in parts:
                self._push_src(p, bc)
            bc.emit(self._op(LogicalOp.JOIN_STR), len(parts))
            self._pop_to_dest(instr.dest, bc)

        else:
            bc.emit(self._op(LogicalOp.NOP))  # unknown → NOP

    # ── helpers ───────────────────────────────────────────────────────────────

    def _op(self, logical: LogicalOp) -> int:
        """Get physical byte for a logical op from the runtime dispatch table."""
        return self._dispatch.encode_op(logical)

    def _push_src(self, src: Optional[str], bc: Bytecode):
        if src is None:
            # push None constant
            idx = bc.const_idx(None)
            bc.emit(self._op(LogicalOp.PUSH_CONST), idx)
            return
        reg = self._reg_alloc.get(src)
        if reg is not None:
            bc.emit(self._op(LogicalOp.PUSH_REG), reg)
        else:
            idx = bc.name_idx(src)
            bc.emit(self._op(LogicalOp.LOAD_NAME), idx)

    def _pop_to_dest(self, dest: Optional[str], bc: Bytecode):
        if dest is None:
            bc.emit(self._op(LogicalOp.POP_DISCARD))
            return
        if dest.startswith("$"):
            reg = self._alloc_reg(dest)
            if reg is not None:
                bc.emit(self._op(LogicalOp.POP_REG), reg)
                return
        # spill to name env
        idx = bc.name_idx(dest)
        bc.emit(self._op(LogicalOp.STORE_NAME), idx)

    def _emit_to_dest(self, dest: Optional[str], logical: LogicalOp, operand: int, bc: Bytecode):
        bc.emit(self._op(logical), operand)
        self._pop_to_dest(dest, bc)

    def _alloc_reg(self, tmp: str) -> Optional[int]:
        if tmp in self._reg_alloc:
            return self._reg_alloc[tmp]
        if self._reg_free:
            reg = self._reg_free.pop(0)
            self._reg_alloc[tmp] = reg
            return reg
        return None  # no register – spill to stack/name

    def _free_tmp(self, tmp: Optional[str]):
        if tmp and tmp in self._reg_alloc:
            reg = self._reg_alloc.pop(tmp)
            self._reg_free.insert(0, reg)


# ─── IR opcode → SR-VM logical op maps ───────────────────────────────────────

_IR_TO_SRVM = {
    IROpcode.ADD:       LogicalOp.ADD_SS,
    IROpcode.SUB:       LogicalOp.SUB_SS,
    IROpcode.MUL:       LogicalOp.MUL_SS,
    IROpcode.DIV:       LogicalOp.DIV_SS,
    IROpcode.FLOOR_DIV: LogicalOp.FDIV_SS,
    IROpcode.MOD:       LogicalOp.MOD_SS,
    IROpcode.POW:       LogicalOp.POW_SS,
    IROpcode.BAND:      LogicalOp.BAND_SS,
    IROpcode.BOR:       LogicalOp.BOR_SS,
    IROpcode.BXOR:      LogicalOp.BXOR_SS,
    IROpcode.LSHIFT:    LogicalOp.LSHIFT_SS,
    IROpcode.RSHIFT:    LogicalOp.RSHIFT_SS,
    IROpcode.AND:       LogicalOp.AND_SS,
    IROpcode.OR:        LogicalOp.OR_SS,
    IROpcode.EQ:        LogicalOp.EQ_SS,
    IROpcode.NE:        LogicalOp.NE_SS,
    IROpcode.LT:        LogicalOp.LT_SS,
    IROpcode.LE:        LogicalOp.LE_SS,
    IROpcode.GT:        LogicalOp.GT_SS,
    IROpcode.GE:        LogicalOp.GE_SS,
    IROpcode.IS:        LogicalOp.IS_SS,
    IROpcode.IS_NOT:    LogicalOp.IS_NOT_SS,
    IROpcode.IN:        LogicalOp.IN_SS,
    IROpcode.NOT_IN:    LogicalOp.NOT_IN_SS,
}

_UNARY_MAP = {
    IROpcode.NEG:  LogicalOp.NEG_S,
    IROpcode.POS:  LogicalOp.POS_S,
    IROpcode.BNOT: LogicalOp.BNOT_S,
    IROpcode.NOT:  LogicalOp.NOT_S,
}


# ─── convenience ─────────────────────────────────────────────────────────────

def compile_module(module: IRModule, dispatch: Optional[RuntimeDispatchTable] = None) -> Dict[str, Bytecode]:
    if dispatch is None:
        dispatch = build_runtime_dispatch()
    compiler = SRVMCompiler(dispatch)
    return compiler.compile_module(module)
