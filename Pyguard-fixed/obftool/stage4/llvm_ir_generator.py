"""
Module 4.2 – LLVM IR Generator
Converts hot IRFunction instructions into LLVM IR (text format).

Strategy:
  • Variables → alloca slots on the stack frame (typed as i64 / double / ptr)
  • Python objects → opaque i8* pointers, operations done via PyObject C-API calls
  • Arithmetic on known-type locals → typed LLVM arithmetic (no boxing)
  • Opaque constants: fold integer literals into LLVM constants wrapped in
    opaque GEP expressions so static analysis can't trivially read them

Generated LLVM IR is text (`.ll` format) ready for `opt | llc` or `clang`.

Emitted per function:
  define i8* @fn_name(i8* %self_env, i8** %args, i32 %nargs) { ... }

C-API calls reference an external `_PyObf_*` vtable that the C extension
provides; this avoids direct `PyObject_*` symbol references in the IR.
"""

from __future__ import annotations
import re
import struct
import random
import hashlib
from typing import Dict, List, Optional, Tuple

from common.ir import IROpcode, IRInstruction, IRFunction, IRModule
from stage4.hot_path_selector import HotPathReport, NATIVE_SAFE_OPS


# ─── LLVM IR helpers ──────────────────────────────────────────────────────────

def _ll_name(s: str) -> str:
    """Sanitise a Python identifier for use as an LLVM value name."""
    return re.sub(r"[^A-Za-z0-9_.]", "_", s)


def _escape_str(s: str) -> str:
    """Escape a Python string for LLVM IR @str constant."""
    result = []
    for ch in s.encode("utf-8"):
        if 32 <= ch <= 126 and ch not in (ord('"'), ord('\\'), ord('%')):
            result.append(chr(ch))
        else:
            result.append(f"\\{ch:02X}")
    result.append("\\00")
    return "".join(result)


# ─── Opaque constant obfuscation ─────────────────────────────────────────────

class OpaqueConstant:
    """
    Wraps an integer constant into a GEP+ptrtoint sequence so the value
    is never visible as a literal in the IR.
    E.g. value 42 → emit a null GEP shifted by 42 bytes then ptrtoint.
    """

    def __init__(self, rng: random.Random):
        self._rng = rng
        self._counter = 0

    def emit(self, value: int, buf: List[str], indent: str = "  ") -> str:
        """Emit LLVM IR that evaluates to the constant and return the SSA name."""
        self._counter += 1
        tmp_ptr = f"%_oc_ptr_{self._counter}"
        tmp_val = f"%_oc_val_{self._counter}"
        xor_key = self._rng.randint(1, 0xFFFFFF)
        obf_val = value ^ xor_key
        # null + obf_val as GEP, then xor back
        buf.append(f"{indent}{tmp_ptr} = getelementptr i8, i8* null, i64 {obf_val}")
        buf.append(f"{indent}{tmp_val}_raw = ptrtoint i8* {tmp_ptr} to i64")
        buf.append(f"{indent}{tmp_val} = xor i64 {tmp_val}_raw, {xor_key}")
        return tmp_val


# ─── Per-function LLVM IR emitter ─────────────────────────────────────────────

class FunctionLLVMEmitter:
    """
    Emits LLVM IR for one hot function.

    All Python values are represented as `i8*` (PyObject*).
    The emitter maintains a type lattice:
      UNKNOWN = i8*  (generic PyObject*)
      INT     = i64  (unboxed, when provably integer)
      FLOAT   = double
    For unboxed types we emit direct LLVM arithmetic.
    For UNKNOWN we emit C-API call stubs.
    """

    # C-API vtable function signatures (provided by C extension runtime)
    _VTABLE = {
        "add":    ("i8*", ["i8*", "i8*"]),
        "sub":    ("i8*", ["i8*", "i8*"]),
        "mul":    ("i8*", ["i8*", "i8*"]),
        "div":    ("i8*", ["i8*", "i8*"]),
        "mod":    ("i8*", ["i8*", "i8*"]),
        "pow":    ("i8*", ["i8*", "i8*"]),
        "eq":     ("i1",  ["i8*", "i8*"]),
        "ne":     ("i1",  ["i8*", "i8*"]),
        "lt":     ("i1",  ["i8*", "i8*"]),
        "le":     ("i1",  ["i8*", "i8*"]),
        "gt":     ("i1",  ["i8*", "i8*"]),
        "ge":     ("i1",  ["i8*", "i8*"]),
        "neg":    ("i8*", ["i8*"]),
        "not_":   ("i1",  ["i8*"]),
        "load":   ("i8*", ["i8*", "i8*"]),   # env lookup
        "store":  ("void",["i8*", "i8*", "i8*"]),
        "call":   ("i8*", ["i8*", "i32", "i8**"]),
        "iter":   ("i8*", ["i8*"]),
        "next":   ("i8*", ["i8*"]),
        "bool":   ("i1",  ["i8*"]),
        "const_int":   ("i8*", ["i64"]),
        "const_float": ("i8*", ["double"]),
        "const_str":   ("i8*", ["i8*"]),
        "const_none":  ("i8*", []),
        "const_true":  ("i8*", []),
        "const_false": ("i8*", []),
        "build_list":  ("i8*", ["i32"]),
        "build_tuple": ("i8*", ["i32"]),
        "list_append": ("void", ["i8*", "i8*"]),
        "return_":     ("void", ["i8*", "i8*"]),  # frame, value
    }

    def __init__(self, fn: IRFunction, fn_name: str, rng: random.Random):
        self._fn       = fn
        self._fn_name  = fn_name
        self._rng      = rng
        self._oc       = OpaqueConstant(rng)
        self._reg_ctr  = 0
        self._label_ctr= 0
        self._tmp_map:  Dict[str, str] = {}   # IR tmp → LLVM SSA name
        self._name_map: Dict[str, str] = {}   # var name → alloca ptr
        self._str_literals: List[Tuple[str, str]] = []  # (ll_name, content)
        self._lines:   List[str] = []
        self._globals: List[str] = []

    def emit(self) -> str:
        """Return complete LLVM IR for this function."""
        body: List[str] = []
        self._emit_prologue(body)
        self._emit_body(body)
        self._emit_epilogue(body)

        # globals (string literals)
        header = self._emit_globals()
        return header + "\n" + "\n".join(body) + "\n}\n"

    # ── prologue / epilogue ───────────────────────────────────────────────────

    def _emit_prologue(self, buf: List[str]):
        mangled = _ll_name(self._fn_name)
        buf.append(f"\n; Function: {self._fn_name}")
        buf.append(f"define i8* @obf_{mangled}(i8* %_env, i8** %_args, i32 %_nargs) nounwind {{")
        buf.append("entry:")
        # Allocate return slot
        buf.append("  %_retval = alloca i8*, align 8")
        buf.append("  store i8* null, i8** %_retval")

    def _emit_epilogue(self, buf: List[str]):
        buf.append("_fn_exit:")
        buf.append("  %_ret = load i8*, i8** %_retval")
        buf.append("  ret i8* %_ret")

    def _emit_globals(self) -> str:
        lines = []
        for ll_name, content in self._str_literals:
            escaped = _escape_str(content)
            byte_len = len(content.encode("utf-8")) + 1
            lines.append(f'@{ll_name} = private unnamed_addr constant [{byte_len} x i8] c"{escaped}", align 1')
        return "\n".join(lines)

    # ── instruction emission ──────────────────────────────────────────────────

    def _emit_body(self, buf: List[str]):
        for instr in self._fn.flat_instructions():
            self._emit_instr(instr, buf)

    def _emit_instr(self, instr: IRInstruction, buf: List[str]):
        op = instr.op

        if op is IROpcode.LABEL:
            lbl = _ll_name(instr.meta.get("name", "lbl"))
            buf.append(f"\n{lbl}:")

        elif op is IROpcode.LOAD_CONST:
            val  = instr.meta.get("value")
            dest = self._new_ssa(instr.dest)
            if val is None:
                buf.append(f"  {dest} = call i8* @_obf_const_none()")
            elif isinstance(val, bool):
                fn = "_obf_const_true" if val else "_obf_const_false"
                buf.append(f"  {dest} = call i8* @{fn}()")
            elif isinstance(val, int):
                # Opaque constant
                oc = self._oc.emit(val, buf)
                buf.append(f"  {dest} = call i8* @_obf_const_int(i64 {oc})")
            elif isinstance(val, float):
                buf.append(f"  {dest} = call i8* @_obf_const_float(double {val})")
            elif isinstance(val, str):
                ll_g = self._intern_str(val)
                buf.append(f"  {dest}_ptr = getelementptr [{len(val.encode())+1} x i8], [{len(val.encode())+1} x i8]* @{ll_g}, i32 0, i32 0")
                buf.append(f"  {dest} = call i8* @_obf_const_str(i8* {dest}_ptr)")
            else:
                buf.append(f"  {dest} = call i8* @_obf_const_none()  ; unsupported const type")

        elif op is IROpcode.LOAD_NAME:
            var  = instr.src1 or instr.dest
            dest = self._new_ssa(instr.dest)
            vptr = self._intern_str(var)
            buf.append(f"  {dest}_key = getelementptr [{len(var.encode())+1} x i8], [{len(var.encode())+1} x i8]* @{vptr}, i32 0, i32 0")
            buf.append(f"  {dest} = call i8* @_obf_load(i8* %_env, i8* {dest}_key)")

        elif op is IROpcode.STORE_NAME:
            src  = self._get_ssa(instr.src1)
            var  = instr.dest
            vptr = self._intern_str(var)
            buf.append(f"  %_sk_{self._next_ctr()} = getelementptr [{len(var.encode())+1} x i8], [{len(var.encode())+1} x i8]* @{vptr}, i32 0, i32 0")
            buf.append(f"  call void @_obf_store(i8* %_env, i8* %_sk_{self._reg_ctr}, i8* {src})")

        elif op is IROpcode.ASSIGN:
            src  = self._get_ssa(instr.src1)
            dest = self._new_ssa(instr.dest)
            buf.append(f"  {dest} = bitcast i8* {src} to i8*")

        # ── arithmetic (typed shortcut for int literals when known) ──────────
        elif op in _OP_TO_VTABLE:
            fn_key = _OP_TO_VTABLE[op]
            ret_ty, arg_tys = self._VTABLE[fn_key]
            s1    = self._get_ssa(instr.src1)
            s2    = self._get_ssa(instr.src2) if instr.src2 else None
            dest  = self._new_ssa(instr.dest)
            args  = f"i8* {s1}" + (f", i8* {s2}" if s2 else "")
            buf.append(f"  {dest} = call {ret_ty} @_obf_{fn_key}({args})")
            if ret_ty == "i1":
                # box boolean result
                tmp = f"{dest}_boxed"
                buf.append(f"  {tmp} = select i1 {dest}, i8* @_obf_const_true(), i8* @_obf_const_false()")

        # ── comparison ───────────────────────────────────────────────────────
        elif op in _CMP_TO_VTABLE:
            fn_key = _CMP_TO_VTABLE[op]
            s1    = self._get_ssa(instr.src1)
            s2    = self._get_ssa(instr.src2)
            dest  = self._new_ssa(instr.dest)
            cmp_r = f"{dest}_cmp"
            buf.append(f"  {cmp_r} = call i1 @_obf_{fn_key}(i8* {s1}, i8* {s2})")
            buf.append(f"  {dest} = select i1 {cmp_r}, i8* @_obf_const_true(), i8* @_obf_const_false()")

        # ── control flow ────────────────────────────────────────────────────
        elif op is IROpcode.JUMP:
            tgt = _ll_name(instr.meta.get("target", "_fn_exit"))
            buf.append(f"  br label %{tgt}")

        elif op is IROpcode.CJUMP:
            cond   = self._get_ssa(instr.src1)
            true_  = _ll_name(instr.meta.get("true", "_fn_exit"))
            false_ = _ll_name(instr.meta.get("false", "_fn_exit"))
            cmp_r  = f"%_cjmp_{self._next_ctr()}"
            buf.append(f"  {cmp_r} = call i1 @_obf_bool(i8* {cond})")
            buf.append(f"  br i1 {cmp_r}, label %{true_}, label %{false_}")

        elif op is IROpcode.RETURN:
            val = self._get_ssa(instr.src1) if instr.src1 else "null"
            buf.append(f"  store i8* {val}, i8** %_retval")
            buf.append(f"  br label %_fn_exit")

        elif op is IROpcode.CALL:
            func   = self._get_ssa(instr.src1)
            args   = instr.meta.get("args", [])
            n_args = len(args)
            # build args array on stack
            arr_ty = f"[{max(1,n_args)} x i8*]"
            arr    = f"%_args_{self._next_ctr()}"
            buf.append(f"  {arr} = alloca {arr_ty}, align 8")
            for i, a in enumerate(args):
                av = self._get_ssa(a[1] if isinstance(a, tuple) else a)
                ep = f"{arr}_ep{i}"
                buf.append(f"  {ep} = getelementptr {arr_ty}, {arr_ty}* {arr}, i32 0, i32 {i}")
                buf.append(f"  store i8* {av}, i8** {ep}")
            arr_ptr = f"{arr}_ptr"
            buf.append(f"  {arr_ptr} = getelementptr {arr_ty}, {arr_ty}* {arr}, i32 0, i32 0")
            dest = self._new_ssa(instr.dest)
            buf.append(f"  {dest} = call i8* @_obf_call(i8* {func}, i32 {n_args}, i8** {arr_ptr})")

        elif op is IROpcode.FOR_ITER:
            iter_  = self._get_ssa(instr.src1)
            dest   = self._new_ssa(instr.dest)
            end_lbl = _ll_name(instr.meta.get("end", "_fn_exit"))
            nxt    = f"%_next_{self._next_ctr()}"
            buf.append(f"  {nxt} = call i8* @_obf_next(i8* {iter_})")
            chk    = f"%_ni_{self._reg_ctr}"
            buf.append(f"  {chk} = icmp eq i8* {nxt}, null")
            buf.append(f"  br i1 {chk}, label %{end_lbl}, label %_iter_ok_{self._reg_ctr}")
            buf.append(f"_iter_ok_{self._reg_ctr}:")
            buf.append(f"  {dest} = bitcast i8* {nxt} to i8*")

        elif op is IROpcode.GET_ITER:
            src  = self._get_ssa(instr.src1)
            dest = self._new_ssa(instr.dest)
            buf.append(f"  {dest} = call i8* @_obf_iter(i8* {src})")

        elif op in (IROpcode.NOP, IROpcode.GLOBAL_DECL,
                    IROpcode.NONLOCAL_DECL, IROpcode.DELETE_NAME):
            buf.append(f"  ; {op.value}")

        else:
            # Generic fallback via vtable
            dest = self._new_ssa(instr.dest) if instr.dest else None
            buf.append(f"  ; unhandled op {op.value}")
            if dest:
                buf.append(f"  {dest} = call i8* @_obf_const_none()")

    # ── SSA helpers ───────────────────────────────────────────────────────────

    def _new_ssa(self, name: Optional[str]) -> str:
        self._reg_ctr += 1
        ssa = f"%v{self._reg_ctr}"
        if name:
            self._tmp_map[name] = ssa
        return ssa

    def _get_ssa(self, name: Optional[str]) -> str:
        if name is None:
            return "null"
        if name in self._tmp_map:
            return self._tmp_map[name]
        # Unknown → synthesise a load
        self._reg_ctr += 1
        return f"%undef_{self._reg_ctr}"

    def _next_ctr(self) -> int:
        self._reg_ctr += 1
        return self._reg_ctr

    def _intern_str(self, s: str) -> str:
        """Intern a string literal as a global and return its ll name."""
        h = hashlib.md5(s.encode()).hexdigest()[:8]
        ll_n = f"_str_{h}"
        if not any(n == ll_n for n, _ in self._str_literals):
            self._str_literals.append((ll_n, s))
        return ll_n


# ─── op → vtable maps ─────────────────────────────────────────────────────────

_OP_TO_VTABLE = {
    IROpcode.ADD: "add", IROpcode.SUB: "sub",
    IROpcode.MUL: "mul", IROpcode.DIV: "div",
    IROpcode.MOD: "mod", IROpcode.POW: "pow",
    IROpcode.NEG: "neg", IROpcode.NOT: "not_",
}

_CMP_TO_VTABLE = {
    IROpcode.EQ: "eq",   IROpcode.NE: "ne",
    IROpcode.LT: "lt",   IROpcode.LE: "le",
    IROpcode.GT: "gt",   IROpcode.GE: "ge",
}


# ─────────────────────────────────────────────────────────────────────────────
# Module-level LLVM IR Generator
# ─────────────────────────────────────────────────────────────────────────────

LLVM_MODULE_HEADER = """\
; ObfTool generated LLVM IR – do not edit
; target triple: x86_64-pc-linux-gnu
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; External vtable declarations
declare i8*  @_obf_add(i8*, i8*)
declare i8*  @_obf_sub(i8*, i8*)
declare i8*  @_obf_mul(i8*, i8*)
declare i8*  @_obf_div(i8*, i8*)
declare i8*  @_obf_mod(i8*, i8*)
declare i8*  @_obf_pow(i8*, i8*)
declare i8*  @_obf_neg(i8*)
declare i1   @_obf_not_(i8*)
declare i1   @_obf_eq(i8*, i8*)
declare i1   @_obf_ne(i8*, i8*)
declare i1   @_obf_lt(i8*, i8*)
declare i1   @_obf_le(i8*, i8*)
declare i1   @_obf_gt(i8*, i8*)
declare i1   @_obf_ge(i8*, i8*)
declare i1   @_obf_bool(i8*)
declare i8*  @_obf_load(i8*, i8*)
declare void @_obf_store(i8*, i8*, i8*)
declare i8*  @_obf_call(i8*, i32, i8**)
declare i8*  @_obf_iter(i8*)
declare i8*  @_obf_next(i8*)
declare i8*  @_obf_const_int(i64)
declare i8*  @_obf_const_float(double)
declare i8*  @_obf_const_str(i8*)
declare i8*  @_obf_const_none()
declare i8*  @_obf_const_true()
declare i8*  @_obf_const_false()
declare i8*  @_obf_build_list(i32)
declare i8*  @_obf_build_tuple(i32)
declare void @_obf_list_append(i8*, i8*)
"""


class LLVMIRGenerator:

    def __init__(self, seed: int = 0):
        self._rng = random.Random(seed)

    def generate(
        self,
        module:  IRModule,
        report:  HotPathReport,
    ) -> Dict[str, str]:
        """
        Returns {fn_name: llvm_ir_text} for each hot function.
        """
        results: Dict[str, str] = {}
        all_fns = self._collect_fns(module)

        for fn_name in report.selected_functions:
            fn = all_fns.get(fn_name)
            if fn is None:
                continue
            emitter = FunctionLLVMEmitter(fn, fn_name, random.Random(self._rng.randint(0, 2**32)))
            fn_ir   = emitter.emit()
            results[fn_name] = fn_ir

        return results

    def generate_module(self, fn_irs: Dict[str, str]) -> str:
        """Combine all function IRs into a single .ll module."""
        parts = [LLVM_MODULE_HEADER]
        parts.extend(fn_irs.values())
        return "\n".join(parts)

    def _collect_fns(self, module: IRModule) -> Dict[str, IRFunction]:
        result = dict(module.functions)
        for cls in module.classes.values():
            for mname, method in cls.methods.items():
                result[f"{cls.name}.{mname}"] = method
        return result


# ─── convenience ─────────────────────────────────────────────────────────────
def generate_llvm_ir(
    module: IRModule,
    report: HotPathReport,
    seed:   int = 0,
) -> tuple[Dict[str, str], str]:
    gen = LLVMIRGenerator(seed=seed)
    fn_irs  = gen.generate(module, report)
    module_ir = gen.generate_module(fn_irs)
    return fn_irs, module_ir
