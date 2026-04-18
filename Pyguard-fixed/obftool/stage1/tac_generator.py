"""
Module 1.2 – Three-Address Code (TAC) IR Generator
Converts an (optionally obfuscated) AST into flat TAC IR for each function.
If a CFG was already built, flattens it.
If not, does a fresh single-pass lowering from the AST.

Output: IRModule with all IRFunction.instructions populated.
"""

from __future__ import annotations
import ast
from typing import Optional, List, Dict, Any

from common.ir import (
    IROpcode, IRInstruction, BasicBlock, CFG,
    IRFunction, IRClass, IRModule
)


# ─── TAC Generator ────────────────────────────────────────────────────────────

class TACGenerator:
    """
    Walks a CFG and flattens it to a linear list of IRInstructions,
    replacing block labels with integer offsets and resolving jumps.
    If no CFG exists, falls through to a direct AST→TAC lowering.
    """

    def generate(self, module: IRModule) -> IRModule:
        """Main entry: process all functions and module body."""
        # Process functions
        for fn in module.functions.values():
            self._process_function(fn)
        for cls in module.classes.values():
            for method in cls.methods.values():
                self._process_function(method)
        # Module-level instructions
        self._generate_module_body(module)
        return module

    # ── function processing ───────────────────────────────────────────────────

    def _process_function(self, fn: IRFunction):
        if fn.cfg:
            fn.instructions = self._flatten_cfg(fn.cfg)
        else:
            ast_node = fn.constants.get("__ast_node__")
            if ast_node:
                lowerer = FunctionLowerer(fn.name)
                fn.instructions = lowerer.lower(ast_node)
        # Recurse into nested functions
        for nested in fn.nested.values():
            if not nested.constants.get("__is_class__"):
                self._process_function(nested)

    def _generate_module_body(self, module: IRModule):
        ast_tree = module.constants.get("__obf_ast__") or module.constants.get("__ast__")
        if ast_tree is None:
            return
        lowerer = ModuleLowerer()
        module.module_instrs = lowerer.lower(ast_tree)

    # ── CFG flattening ────────────────────────────────────────────────────────

    def _flatten_cfg(self, cfg: CFG) -> List[IRInstruction]:
        """
        Linearise CFG blocks in topological order.
        Insert LABEL instructions at block entries.
        Resolve JUMP/CJUMP targets from block labels to labels.
        (Actual numeric offsets are computed later by the VM compiler.)
        """
        order = self._topo_order(cfg)
        result: List[IRInstruction] = []

        for lbl in order:
            blk = cfg.blocks[lbl]
            # Block entry label
            result.append(IRInstruction(
                op=IROpcode.LABEL,
                meta={"name": lbl}
            ))
            for instr in blk.instructions:
                result.append(instr.clone())

        return result

    def _topo_order(self, cfg: CFG) -> List[str]:
        visited, order = set(), []
        def dfs(lbl):
            if lbl in visited or lbl not in cfg.blocks:
                return
            visited.add(lbl)
            for s in cfg.blocks[lbl].successors:
                dfs(s)
            order.append(lbl)
        if cfg.entry:
            dfs(cfg.entry)
        # Add any unreachable blocks at the end
        for lbl in cfg.blocks:
            if lbl not in visited:
                dfs(lbl)
        return list(reversed(order))


# ─── Direct AST → TAC Lowerer ─────────────────────────────────────────────────

class _BaseLowerer:
    """
    Shared machinery for both FunctionLowerer and ModuleLowerer.
    Implements a complete Python AST → TAC translation.
    """

    def __init__(self, context_name: str = "<module>"):
        self._ctx      = context_name
        self._tmp_ctr  = 0
        self._lbl_ctr  = 0
        self._instrs:  List[IRInstruction] = []
        self._break_stack:    List[str] = []
        self._continue_stack: List[str] = []

    # ── emit helpers ──────────────────────────────────────────────────────────

    def _emit(self, op: IROpcode, dest=None, src1=None, src2=None, **meta) -> IRInstruction:
        i = IRInstruction(op=op, dest=dest, src1=src1, src2=src2, meta=meta)
        self._instrs.append(i)
        return i

    def _tmp(self) -> str:
        self._tmp_ctr += 1
        return f"$t{self._tmp_ctr}"

    def _label(self, hint: str = "") -> str:
        self._lbl_ctr += 1
        return f"L{self._lbl_ctr}_{hint}" if hint else f"L{self._lbl_ctr}"

    def _mark(self, lbl: str):
        self._emit(IROpcode.LABEL, meta={"name": lbl})

    # ── statement dispatch ────────────────────────────────────────────────────

    def _lower_stmts(self, stmts: list):
        for s in stmts:
            self._lower_stmt(s)

    def _lower_stmt(self, node: ast.stmt):
        tp = type(node)
        if   tp is ast.Pass:      pass
        elif tp is ast.Expr:      self._lower_expr(node.value)
        elif tp is ast.Assign:    self._lower_assign(node)
        elif tp is ast.AnnAssign: self._lower_ann_assign(node)
        elif tp is ast.AugAssign: self._lower_aug_assign(node)
        elif tp is ast.Return:    self._lower_return(node)
        elif tp is ast.If:        self._lower_if(node)
        elif tp is ast.While:     self._lower_while(node)
        elif tp is ast.For:       self._lower_for(node)
        elif tp is ast.Break:     self._lower_break()
        elif tp is ast.Continue:  self._lower_continue()
        elif tp is ast.Try:       self._lower_try(node)
        elif tp is ast.With:      self._lower_with(node)
        elif tp is ast.Raise:     self._lower_raise(node)
        elif tp is ast.Delete:    self._lower_delete(node)
        elif tp is ast.Global:
            for n in node.names:
                self._emit(IROpcode.GLOBAL_DECL, dest=n)
        elif tp is ast.Nonlocal:
            for n in node.names:
                self._emit(IROpcode.NONLOCAL_DECL, dest=n)
        elif tp in (ast.FunctionDef, ast.AsyncFunctionDef):
            self._lower_funcdef(node)
        elif tp is ast.ClassDef:
            self._lower_classdef(node)
        elif tp in (ast.Import, ast.ImportFrom):
            self._lower_import(node)
        elif tp is ast.Assert:
            test = self._lower_expr(node.test)
            msg  = self._lower_expr(node.msg) if node.msg else None
            self._emit(IROpcode.ASSERT, src1=test, src2=msg)
        else:
            self._emit(IROpcode.NOP, meta={"raw": ast.unparse(node)})

    # ── assignments ───────────────────────────────────────────────────────────

    def _lower_assign(self, node: ast.Assign):
        src = self._lower_expr(node.value)
        for tgt in node.targets:
            self._assign_target(tgt, src)

    def _lower_ann_assign(self, node: ast.AnnAssign):
        if node.value:
            src = self._lower_expr(node.value)
            self._assign_target(node.target, src)

    def _lower_aug_assign(self, node: ast.AugAssign):
        op_map = {
            ast.Add: IROpcode.ADD, ast.Sub: IROpcode.SUB,
            ast.Mult: IROpcode.MUL, ast.Div: IROpcode.DIV,
            ast.FloorDiv: IROpcode.FLOOR_DIV, ast.Mod: IROpcode.MOD,
            ast.Pow: IROpcode.POW, ast.BitAnd: IROpcode.BAND,
            ast.BitOr: IROpcode.BOR, ast.BitXor: IROpcode.BXOR,
            ast.LShift: IROpcode.LSHIFT, ast.RShift: IROpcode.RSHIFT,
        }
        old_val = self._load_target(node.target)
        rhs     = self._lower_expr(node.value)
        op      = op_map.get(type(node.op), IROpcode.ADD)
        result  = self._tmp()
        self._emit(op, dest=result, src1=old_val, src2=rhs)
        self._assign_target(node.target, result)

    def _load_target(self, tgt: ast.expr) -> str:
        if isinstance(tgt, ast.Name):
            tmp = self._tmp()
            self._emit(IROpcode.LOAD_NAME, dest=tmp, src1=tgt.id)
            return tmp
        return self._lower_expr(tgt)

    def _assign_target(self, tgt: ast.expr, src: str):
        if isinstance(tgt, ast.Name):
            self._emit(IROpcode.STORE_NAME, dest=tgt.id, src1=src)
        elif isinstance(tgt, ast.Attribute):
            obj = self._lower_expr(tgt.value)
            self._emit(IROpcode.STORE_ATTR, src1=obj, src2=src,
                       meta={"attr": tgt.attr})
        elif isinstance(tgt, ast.Subscript):
            obj = self._lower_expr(tgt.value)
            idx = self._lower_expr(tgt.slice)
            self._emit(IROpcode.STORE_INDEX, src1=obj, src2=idx,
                       meta={"value": src})
        elif isinstance(tgt, (ast.List, ast.Tuple)):
            targets = []
            for i, elt in enumerate(tgt.elts):
                if isinstance(elt, ast.Name):
                    targets.append(elt.id)
                else:
                    targets.append(ast.unparse(elt))
            self._emit(IROpcode.UNPACK_SEQ, src1=src,
                       meta={"targets": targets, "n": len(targets)})

    # ── control flow ──────────────────────────────────────────────────────────

    def _lower_return(self, node: ast.Return):
        val = self._lower_expr(node.value) if node.value else None
        self._emit(IROpcode.RETURN, src1=val)

    def _lower_raise(self, node: ast.Raise):
        exc  = self._lower_expr(node.exc)  if node.exc  else None
        cause = self._lower_expr(node.cause) if node.cause else None
        self._emit(IROpcode.RAISE, src1=exc, src2=cause)

    def _lower_break(self):
        tgt = self._break_stack[-1] if self._break_stack else "__break__"
        self._emit(IROpcode.JUMP, meta={"target": tgt})

    def _lower_continue(self):
        tgt = self._continue_stack[-1] if self._continue_stack else "__continue__"
        self._emit(IROpcode.JUMP, meta={"target": tgt})

    def _lower_if(self, node: ast.If):
        cond      = self._lower_expr(node.test)
        else_lbl  = self._label("else")
        merge_lbl = self._label("merge")
        false_tgt = else_lbl if node.orelse else merge_lbl

        self._emit(IROpcode.CJUMP, src1=cond,
                   meta={"true": "$fall", "false": false_tgt})
        self._lower_stmts(node.body)
        self._emit(IROpcode.JUMP, meta={"target": merge_lbl})

        if node.orelse:
            self._mark(else_lbl)
            self._lower_stmts(node.orelse)
            self._emit(IROpcode.JUMP, meta={"target": merge_lbl})

        self._mark(merge_lbl)

    def _lower_while(self, node: ast.While):
        cond_lbl  = self._label("while_cond")
        body_lbl  = self._label("while_body")
        end_lbl   = self._label("while_end")

        self._emit(IROpcode.JUMP, meta={"target": cond_lbl})
        self._mark(cond_lbl)
        cond = self._lower_expr(node.test)
        self._emit(IROpcode.CJUMP, src1=cond,
                   meta={"true": body_lbl, "false": end_lbl})
        self._mark(body_lbl)

        self._break_stack.append(end_lbl)
        self._continue_stack.append(cond_lbl)
        self._lower_stmts(node.body)
        self._break_stack.pop()
        self._continue_stack.pop()

        self._emit(IROpcode.JUMP, meta={"target": cond_lbl})
        self._mark(end_lbl)

    def _lower_for(self, node: ast.For):
        header_lbl = self._label("for_hdr")
        body_lbl   = self._label("for_body")
        end_lbl    = self._label("for_end")

        iter_src = self._lower_expr(node.iter)
        iter_tmp = self._tmp()
        self._emit(IROpcode.GET_ITER, dest=iter_tmp, src1=iter_src)

        self._emit(IROpcode.JUMP, meta={"target": header_lbl})
        self._mark(header_lbl)
        val = self._tmp()
        self._emit(IROpcode.FOR_ITER, dest=val, src1=iter_tmp,
                   meta={"end": end_lbl})
        self._mark(body_lbl)
        self._assign_target(node.target, val)

        self._break_stack.append(end_lbl)
        self._continue_stack.append(header_lbl)
        self._lower_stmts(node.body)
        self._break_stack.pop()
        self._continue_stack.pop()

        self._emit(IROpcode.JUMP, meta={"target": header_lbl})
        self._mark(end_lbl)

    def _lower_try(self, node: ast.Try):
        handler_lbl  = self._label("except")
        finally_lbl  = self._label("finally") if node.finalbody else None
        end_lbl      = self._label("try_end")

        self._emit(IROpcode.SETUP_EXCEPT, meta={"handler": handler_lbl})
        self._lower_stmts(node.body)
        self._emit(IROpcode.END_EXCEPT)
        self._emit(IROpcode.JUMP, meta={"target": end_lbl})

        self._mark(handler_lbl)
        exc_tmp = self._tmp()
        self._emit(IROpcode.PUSH_EXCEPT, dest=exc_tmp)
        for handler in node.handlers:
            if handler.name:
                self._emit(IROpcode.STORE_NAME, dest=handler.name, src1=exc_tmp)
            self._lower_stmts(handler.body)
        self._emit(IROpcode.POP_EXCEPT)
        self._emit(IROpcode.JUMP, meta={"target": end_lbl})

        if finally_lbl:
            self._mark(finally_lbl)
            self._lower_stmts(node.finalbody)

        self._mark(end_lbl)

    def _lower_with(self, node: ast.With):
        mgr_tmps = []
        for item in node.items:
            mgr = self._lower_expr(item.context_expr)
            val = self._tmp()
            self._emit(IROpcode.WITH_ENTER, dest=val, src1=mgr)
            if item.optional_vars:
                self._assign_target(item.optional_vars, val)
            mgr_tmps.append(mgr)
        self._lower_stmts(node.body)
        for mgr in reversed(mgr_tmps):
            self._emit(IROpcode.WITH_EXIT, src1=mgr)

    def _lower_delete(self, node: ast.Delete):
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                self._emit(IROpcode.DELETE_NAME, dest=tgt.id)
            else:
                self._emit(IROpcode.NOP, meta={"del": ast.unparse(tgt)})

    # ── definitions ───────────────────────────────────────────────────────────

    def _lower_funcdef(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        tmp = self._tmp()
        self._emit(IROpcode.MAKE_FUNCTION, dest=tmp,
                   meta={"name": node.name, "ast_node": node,
                         "is_async": isinstance(node, ast.AsyncFunctionDef)})
        self._emit(IROpcode.STORE_NAME, dest=node.name, src1=tmp)

    def _lower_classdef(self, node: ast.ClassDef):
        tmp = self._tmp()
        self._emit(IROpcode.MAKE_CLASS, dest=tmp,
                   meta={"name": node.name, "ast_node": node})
        self._emit(IROpcode.STORE_NAME, dest=node.name, src1=tmp)

    # ── imports ───────────────────────────────────────────────────────────────

    def _lower_import(self, node: ast.stmt):
        if isinstance(node, ast.Import):
            for alias in node.names:
                tmp = self._tmp()
                self._emit(IROpcode.IMPORT_NAME, dest=tmp,
                            meta={"module": alias.name})
                name = alias.asname or alias.name.split(".")[0]
                self._emit(IROpcode.STORE_NAME, dest=name, src1=tmp)
        elif isinstance(node, ast.ImportFrom):
            mod_tmp = self._tmp()
            self._emit(IROpcode.IMPORT_NAME, dest=mod_tmp,
                        meta={"module": node.module or ""})
            for alias in node.names:
                if alias.name == "*":
                    self._emit(IROpcode.IMPORT_STAR, src1=mod_tmp)
                else:
                    attr_tmp = self._tmp()
                    self._emit(IROpcode.IMPORT_FROM, dest=attr_tmp, src1=mod_tmp,
                                meta={"name": alias.name})
                    self._emit(IROpcode.STORE_NAME,
                                dest=alias.asname or alias.name, src1=attr_tmp)

    # ── expression lowering ───────────────────────────────────────────────────

    def _lower_expr(self, node: ast.expr) -> str:
        tmp = self._tmp()
        tp  = type(node)

        if tp is ast.Constant:
            self._emit(IROpcode.LOAD_CONST, dest=tmp, meta={"value": node.value})

        elif tp is ast.Name:
            self._emit(IROpcode.LOAD_NAME, dest=tmp, src1=node.id)

        elif tp is ast.BinOp:
            left  = self._lower_expr(node.left)
            right = self._lower_expr(node.right)
            op    = _BINOP[type(node.op)]
            self._emit(op, dest=tmp, src1=left, src2=right)

        elif tp is ast.UnaryOp:
            operand = self._lower_expr(node.operand)
            op      = _UNARY[type(node.op)]
            self._emit(op, dest=tmp, src1=operand)

        elif tp is ast.BoolOp:
            parts = [self._lower_expr(v) for v in node.values]
            op = IROpcode.AND if isinstance(node.op, ast.And) else IROpcode.OR
            cur = parts[0]
            for p in parts[1:]:
                nxt = self._tmp()
                self._emit(op, dest=nxt, src1=cur, src2=p)
                cur = nxt
            self._emit(IROpcode.ASSIGN, dest=tmp, src1=cur)

        elif tp is ast.Compare:
            left = self._lower_expr(node.left)
            parts = []
            cur   = left
            for cmp_op, comparator in zip(node.ops, node.comparators):
                right = self._lower_expr(comparator)
                ir_op = _CMP[type(cmp_op)]
                part  = self._tmp()
                self._emit(ir_op, dest=part, src1=cur, src2=right)
                parts.append(part)
                cur = right
            if len(parts) == 1:
                self._emit(IROpcode.ASSIGN, dest=tmp, src1=parts[0])
            else:
                # chain: a < b < c ↔ (a<b) AND (b<c)
                cur = parts[0]
                for p in parts[1:]:
                    nxt = self._tmp()
                    self._emit(IROpcode.AND, dest=nxt, src1=cur, src2=p)
                    cur = nxt
                self._emit(IROpcode.ASSIGN, dest=tmp, src1=cur)

        elif tp is ast.Call:
            func = self._lower_expr(node.func)
            args = []
            for a in node.args:
                if isinstance(a, ast.Starred):
                    v = self._lower_expr(a.value)
                    args.append(("*", v))
                else:
                    args.append(("", self._lower_expr(a)))
            kwargs = {}
            starargs = []
            for kw in node.keywords:
                if kw.arg is None:  # **kw
                    starargs.append(self._lower_expr(kw.value))
                else:
                    kwargs[kw.arg] = self._lower_expr(kw.value)
            self._emit(IROpcode.CALL, dest=tmp, src1=func,
                       meta={"args": args, "kwargs": kwargs, "starargs": starargs})

        elif tp is ast.Attribute:
            obj = self._lower_expr(node.value)
            self._emit(IROpcode.LOAD_ATTR, dest=tmp, src1=obj,
                       meta={"attr": node.attr})

        elif tp is ast.Subscript:
            obj = self._lower_expr(node.value)
            idx = self._lower_expr(node.slice)
            self._emit(IROpcode.LOAD_INDEX, dest=tmp, src1=obj, src2=idx)

        elif tp is ast.IfExp:
            cond   = self._lower_expr(node.test)
            true_l = self._label("ternary_t")
            end_l  = self._label("ternary_e")
            self._emit(IROpcode.CJUMP, src1=cond,
                       meta={"true": true_l, "false": end_l})
            self._mark(true_l)
            tv = self._lower_expr(node.body)
            self._emit(IROpcode.ASSIGN, dest=tmp, src1=tv)
            fv = self._lower_expr(node.orelse)
            self._emit(IROpcode.ASSIGN, dest=tmp, src1=fv)
            self._mark(end_l)

        elif tp is ast.List:
            items = [self._lower_expr(e) for e in node.elts]
            self._emit(IROpcode.BUILD_LIST, dest=tmp, meta={"items": items})

        elif tp is ast.Tuple:
            items = [self._lower_expr(e) for e in node.elts]
            self._emit(IROpcode.BUILD_TUPLE, dest=tmp, meta={"items": items})

        elif tp is ast.Set:
            items = [self._lower_expr(e) for e in node.elts]
            self._emit(IROpcode.BUILD_SET, dest=tmp, meta={"items": items})

        elif tp is ast.Dict:
            keys   = [self._lower_expr(k) if k else None for k in node.keys]
            values = [self._lower_expr(v) for v in node.values]
            self._emit(IROpcode.BUILD_DICT, dest=tmp,
                       meta={"keys": keys, "values": values})

        elif tp is ast.Yield:
            val = self._lower_expr(node.value) if node.value else None
            self._emit(IROpcode.YIELD, dest=tmp, src1=val)

        elif tp is ast.YieldFrom:
            val = self._lower_expr(node.value)
            self._emit(IROpcode.YIELD_FROM, dest=tmp, src1=val)

        elif tp is ast.Lambda:
            self._emit(IROpcode.MAKE_FUNCTION, dest=tmp,
                       meta={"name": "<lambda>", "ast_node": node})

        elif tp is ast.JoinedStr:
            parts = [self._lower_expr(v) for v in node.values]
            self._emit(IROpcode.JOIN_STR, dest=tmp, meta={"parts": parts})

        elif tp is ast.FormattedValue:
            val = self._lower_expr(node.value)
            self._emit(IROpcode.FORMAT_VALUE, dest=tmp, src1=val,
                       meta={"conversion": node.conversion})

        elif tp is ast.NamedExpr:
            val = self._lower_expr(node.value)
            self._emit(IROpcode.ASSIGN, dest=tmp, src1=val)
            self._emit(IROpcode.STORE_NAME, dest=node.target.id, src1=tmp)

        elif tp is ast.Starred:
            val = self._lower_expr(node.value)
            self._emit(IROpcode.ASSIGN, dest=tmp, src1=val, meta={"starred": True})

        elif tp is ast.Slice:
            lo   = self._lower_expr(node.lower) if node.lower else None
            hi   = self._lower_expr(node.upper) if node.upper else None
            step = self._lower_expr(node.step)  if node.step  else None
            self._emit(IROpcode.BUILD_SLICE, dest=tmp, src1=lo, src2=hi,
                       meta={"step": step})

        elif tp is ast.ListComp:
            self._emit(IROpcode.LOAD_CONST, dest=tmp,
                       meta={"value": None, "comprehension": ast.unparse(node)})

        elif tp is ast.GeneratorExp:
            self._emit(IROpcode.LOAD_CONST, dest=tmp,
                       meta={"value": None, "genexp": ast.unparse(node)})

        elif tp is ast.DictComp:
            self._emit(IROpcode.LOAD_CONST, dest=tmp,
                       meta={"value": None, "comprehension": ast.unparse(node)})

        elif tp is ast.SetComp:
            self._emit(IROpcode.LOAD_CONST, dest=tmp,
                       meta={"value": None, "comprehension": ast.unparse(node)})

        else:
            self._emit(IROpcode.LOAD_CONST, dest=tmp,
                       meta={"value": None, "raw_expr": ast.unparse(node)})

        return tmp


class FunctionLowerer(_BaseLowerer):
    def lower(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> List[IRInstruction]:
        self._lower_stmts(node.body)
        # Ensure there's a RETURN at the end
        if not self._instrs or self._instrs[-1].op is not IROpcode.RETURN:
            self._emit(IROpcode.RETURN, src1=None)
        return self._instrs


class ModuleLowerer(_BaseLowerer):
    def lower(self, tree: ast.Module) -> List[IRInstruction]:
        self._lower_stmts(tree.body)
        return self._instrs


# ─── operator maps ────────────────────────────────────────────────────────────

_BINOP = {
    ast.Add: IROpcode.ADD, ast.Sub: IROpcode.SUB,
    ast.Mult: IROpcode.MUL, ast.Div: IROpcode.DIV,
    ast.FloorDiv: IROpcode.FLOOR_DIV, ast.Mod: IROpcode.MOD,
    ast.Pow: IROpcode.POW, ast.MatMult: IROpcode.MATMUL,
    ast.BitAnd: IROpcode.BAND, ast.BitOr: IROpcode.BOR,
    ast.BitXor: IROpcode.BXOR, ast.LShift: IROpcode.LSHIFT,
    ast.RShift: IROpcode.RSHIFT,
}

_UNARY = {
    ast.USub: IROpcode.NEG,
    ast.UAdd: IROpcode.POS,
    ast.Invert: IROpcode.BNOT,
    ast.Not: IROpcode.NOT,
}

_CMP = {
    ast.Eq: IROpcode.EQ, ast.NotEq: IROpcode.NE,
    ast.Lt: IROpcode.LT, ast.LtE: IROpcode.LE,
    ast.Gt: IROpcode.GT, ast.GtE: IROpcode.GE,
    ast.Is: IROpcode.IS, ast.IsNot: IROpcode.IS_NOT,
    ast.In: IROpcode.IN, ast.NotIn: IROpcode.NOT_IN,
}


# ─── convenience ─────────────────────────────────────────────────────────────

def generate_tac(module: IRModule) -> IRModule:
    return TACGenerator().generate(module)
