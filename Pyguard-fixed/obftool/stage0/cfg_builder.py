"""
Module 0.2 – CFG Builder
Builds a Control Flow Graph (basic blocks + edges) for each function.
Works from raw AST nodes stored in IRFunction.constants['__ast_node__'].
"""

from __future__ import annotations
import ast
from typing import Optional
from common.ir import (
    IROpcode, IRInstruction, BasicBlock, CFG,
    IRFunction, IRClass, IRModule
)


class CFGBuilder:
    """
    Converts an AST function body into a CFG of BasicBlocks.
    Each block ends with a terminator (JUMP / CJUMP / RETURN / RAISE).
    """

    def __init__(self):
        self._block_counter = 0
        self._tmp_counter   = 0
        self._current: Optional[BasicBlock] = None
        self._cfg: Optional[CFG] = None

    # ── public ────────────────────────────────────────────────────────────────

    def build(self, fn: IRFunction) -> CFG:
        """Build and attach a CFG to the given IRFunction."""
        ast_node = fn.constants.get("__ast_node__")
        if ast_node is None:
            # No AST – wrap flat instruction list into a single block
            return self._wrap_flat(fn)

        self._block_counter = 0
        self._tmp_counter   = 0
        cfg = CFG()
        self._cfg = cfg

        entry = self._new_block("entry")
        cfg.entry = entry.label
        cfg.add_block(entry)
        self._current = entry

        self._visit_stmts(ast_node.body)

        # Ensure current block is terminated
        if self._current and not self._current.terminator():
            self._emit(IROpcode.RETURN, src1=None)

        # Mark exit block(s)
        for lbl, blk in cfg.blocks.items():
            t = blk.terminator()
            if t and t.op in (IROpcode.RETURN, IROpcode.RAISE):
                cfg.exit_ = lbl

        fn.cfg = cfg
        return cfg

    def build_module(self, module: IRModule) -> IRModule:
        for fn in module.functions.values():
            if fn.constants.get("__ast_node__"):
                self.build(fn)
        for cls in module.classes.values():
            for method in cls.methods.values():
                if method.constants.get("__ast_node__"):
                    self.build(method)
        return module

    # ── block helpers ─────────────────────────────────────────────────────────

    def _new_block(self, hint: str = "") -> BasicBlock:
        self._block_counter += 1
        label = f"B{self._block_counter}_{hint}" if hint else f"B{self._block_counter}"
        return BasicBlock(label=label)

    def _switch_to(self, block: BasicBlock):
        self._cfg.add_block(block)
        self._current = block

    def _emit(self, op: IROpcode, dest=None, src1=None, src2=None, **meta):
        instr = IRInstruction(op=op, dest=dest, src1=src1, src2=src2, meta=meta)
        self._current.add(instr)
        return instr

    def _new_tmp(self) -> str:
        self._tmp_counter += 1
        return f"$t{self._tmp_counter}"

    # ── statement visitors ────────────────────────────────────────────────────

    def _visit_stmts(self, stmts: list[ast.stmt]):
        for s in stmts:
            if self._current is None:
                break  # unreachable code
            self._visit_stmt(s)

    def _visit_stmt(self, node: ast.stmt):
        tp = type(node)

        if tp is ast.Pass:
            self._emit(IROpcode.NOP)

        elif tp is ast.Expr:
            tmp = self._visit_expr(node.value)
            self._emit(IROpcode.NOP, meta={"discard": tmp})

        elif tp is ast.Assign:
            src = self._visit_expr(node.value)
            for t in node.targets:
                self._assign_target(t, src)

        elif tp is ast.AnnAssign:
            if node.value:
                src = self._visit_expr(node.value)
                self._assign_target(node.target, src)

        elif tp is ast.AugAssign:
            self._visit_augassign(node)

        elif tp is ast.Return:
            val = self._visit_expr(node.value) if node.value else None
            self._emit(IROpcode.RETURN, src1=val)
            # unreachable – null out current so we stop emitting
            self._current = None

        elif tp is ast.If:
            self._visit_if(node)

        elif tp is ast.While:
            self._visit_while(node)

        elif tp is ast.For:
            self._visit_for(node)

        elif tp is ast.Break:
            # Emit placeholder – loop builder resolves target later
            self._emit(IROpcode.JUMP, meta={"target": "__break__"})
            self._current = None

        elif tp is ast.Continue:
            self._emit(IROpcode.JUMP, meta={"target": "__continue__"})
            self._current = None

        elif tp is ast.Try:
            self._visit_try(node)

        elif tp is ast.With:
            self._visit_with(node)

        elif tp is ast.Raise:
            exc = self._visit_expr(node.exc) if node.exc else None
            self._emit(IROpcode.RAISE, src1=exc)
            self._current = None

        elif tp is ast.Delete:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._emit(IROpcode.DELETE_NAME, dest=t.id)

        elif tp is ast.Global:
            for n in node.names:
                self._emit(IROpcode.GLOBAL_DECL, dest=n)

        elif tp is ast.Nonlocal:
            for n in node.names:
                self._emit(IROpcode.NONLOCAL_DECL, dest=n)

        elif tp in (ast.FunctionDef, ast.AsyncFunctionDef):
            self._emit(
                IROpcode.MAKE_FUNCTION, dest=node.name,
                meta={"name": node.name, "ast_node": node}
            )
            self._emit(IROpcode.STORE_NAME, dest=node.name, src1=node.name)

        elif tp is ast.ClassDef:
            self._emit(
                IROpcode.MAKE_CLASS, dest=node.name,
                meta={"name": node.name, "ast_node": node}
            )
            self._emit(IROpcode.STORE_NAME, dest=node.name, src1=node.name)

        elif tp in (ast.Import, ast.ImportFrom):
            self._visit_import(node)

        elif tp is ast.Assert:
            test = self._visit_expr(node.test)
            msg  = self._visit_expr(node.msg) if node.msg else None
            self._emit(IROpcode.ASSERT, src1=test, src2=msg)

        else:
            # Fallback – emit NOP with raw node
            self._emit(IROpcode.NOP, meta={"raw_ast": node})

    # ── if / while / for ─────────────────────────────────────────────────────

    def _visit_if(self, node: ast.If):
        cond = self._visit_expr(node.test)

        then_blk = self._new_block("then")
        else_blk = self._new_block("else") if node.orelse else None
        merge_blk = self._new_block("merge")

        false_target = else_blk.label if else_blk else merge_blk.label
        self._emit(IROpcode.CJUMP, src1=cond,
                   meta={"true": then_blk.label, "false": false_target})
        self._cfg.add_edge(self._current.label, then_blk.label)
        self._cfg.add_edge(self._current.label, false_target)

        # then branch
        self._switch_to(then_blk)
        self._visit_stmts(node.body)
        if self._current:
            self._emit(IROpcode.JUMP, meta={"target": merge_blk.label})
            self._cfg.add_edge(self._current.label, merge_blk.label)

        # else branch
        if else_blk:
            self._switch_to(else_blk)
            self._visit_stmts(node.orelse)
            if self._current:
                self._emit(IROpcode.JUMP, meta={"target": merge_blk.label})
                self._cfg.add_edge(self._current.label, merge_blk.label)

        self._switch_to(merge_blk)

    def _visit_while(self, node: ast.While):
        cond_blk  = self._new_block("while_cond")
        body_blk  = self._new_block("while_body")
        merge_blk = self._new_block("while_end")

        # Jump to cond
        self._emit(IROpcode.JUMP, meta={"target": cond_blk.label})
        self._cfg.add_edge(self._current.label, cond_blk.label)

        # Condition block
        self._switch_to(cond_blk)
        cond = self._visit_expr(node.test)
        self._emit(IROpcode.CJUMP, src1=cond,
                   meta={"true": body_blk.label, "false": merge_blk.label})
        self._cfg.add_edge(cond_blk.label, body_blk.label)
        self._cfg.add_edge(cond_blk.label, merge_blk.label)

        # Body
        self._switch_to(body_blk)
        self._visit_stmts(node.body)
        if self._current:
            self._emit(IROpcode.JUMP, meta={"target": cond_blk.label})
            self._cfg.add_edge(self._current.label, cond_blk.label)

        # else clause (if no break)
        if node.orelse:
            else_blk = self._new_block("while_else")
            self._cfg.add_edge(cond_blk.label, else_blk.label)
            self._switch_to(else_blk)
            self._visit_stmts(node.orelse)
            if self._current:
                self._emit(IROpcode.JUMP, meta={"target": merge_blk.label})
                self._cfg.add_edge(self._current.label, merge_blk.label)

        self._switch_to(merge_blk)

    def _visit_for(self, node: ast.For):
        iter_tmp  = self._new_tmp()
        body_blk  = self._new_block("for_body")
        merge_blk = self._new_block("for_end")

        iter_src = self._visit_expr(node.iter)
        self._emit(IROpcode.GET_ITER, dest=iter_tmp, src1=iter_src)

        header_blk = self._new_block("for_header")
        self._emit(IROpcode.JUMP, meta={"target": header_blk.label})
        self._cfg.add_edge(self._current.label, header_blk.label)

        self._switch_to(header_blk)
        val_tmp = self._new_tmp()
        self._emit(IROpcode.FOR_ITER, dest=val_tmp, src1=iter_tmp,
                   meta={"end": merge_blk.label})
        self._cfg.add_edge(header_blk.label, body_blk.label)
        self._cfg.add_edge(header_blk.label, merge_blk.label)

        self._switch_to(body_blk)
        self._assign_target(node.target, val_tmp)
        self._visit_stmts(node.body)
        if self._current:
            self._emit(IROpcode.JUMP, meta={"target": header_blk.label})
            self._cfg.add_edge(self._current.label, header_blk.label)

        self._switch_to(merge_blk)

    # ── try / with ────────────────────────────────────────────────────────────

    def _visit_try(self, node: ast.Try):
        handler_blk = self._new_block("except")
        finally_blk = self._new_block("finally") if node.finalbody else None
        merge_blk   = self._new_block("try_end")

        self._emit(IROpcode.SETUP_EXCEPT, meta={"handler": handler_blk.label})
        self._cfg.add_edge(self._current.label, handler_blk.label)

        try_blk = self._new_block("try_body")
        self._emit(IROpcode.JUMP, meta={"target": try_blk.label})
        self._cfg.add_edge(self._current.label, try_blk.label)

        self._switch_to(try_blk)
        self._visit_stmts(node.body)
        if self._current:
            self._emit(IROpcode.END_EXCEPT)
            self._emit(IROpcode.JUMP, meta={"target": merge_blk.label})
            self._cfg.add_edge(self._current.label, merge_blk.label)

        # handler blocks
        self._switch_to(handler_blk)
        exc_tmp = self._new_tmp()
        self._emit(IROpcode.PUSH_EXCEPT, dest=exc_tmp)
        for handler in node.handlers:
            if handler.name:
                self._emit(IROpcode.STORE_NAME, dest=handler.name, src1=exc_tmp)
            self._visit_stmts(handler.body)
        self._emit(IROpcode.POP_EXCEPT)
        if self._current:
            self._emit(IROpcode.JUMP, meta={"target": merge_blk.label})
            self._cfg.add_edge(self._current.label, merge_blk.label)

        if finally_blk:
            self._switch_to(finally_blk)
            self._visit_stmts(node.finalbody)
            if self._current:
                self._emit(IROpcode.JUMP, meta={"target": merge_blk.label})
                self._cfg.add_edge(self._current.label, merge_blk.label)

        self._switch_to(merge_blk)

    def _visit_with(self, node: ast.With):
        for item in node.items:
            mgr_tmp = self._visit_expr(item.context_expr)
            val_tmp = self._new_tmp()
            self._emit(IROpcode.WITH_ENTER, dest=val_tmp, src1=mgr_tmp)
            if item.optional_vars:
                self._assign_target(item.optional_vars, val_tmp)
        self._visit_stmts(node.body)
        self._emit(IROpcode.WITH_EXIT, src1=mgr_tmp)

    # ── expression visitors ───────────────────────────────────────────────────

    def _visit_expr(self, node: ast.expr) -> str:
        """Visit an expression, returning the tmp variable holding the result."""
        tp = type(node)
        tmp = self._new_tmp()

        if tp is ast.Constant:
            self._emit(IROpcode.LOAD_CONST, dest=tmp, meta={"value": node.value})

        elif tp is ast.Name:
            self._emit(IROpcode.LOAD_NAME, dest=tmp, src1=node.id)

        elif tp is ast.BinOp:
            left  = self._visit_expr(node.left)
            right = self._visit_expr(node.right)
            op    = _BINOP_MAP.get(type(node.op), IROpcode.ADD)
            self._emit(op, dest=tmp, src1=left, src2=right)

        elif tp is ast.UnaryOp:
            operand = self._visit_expr(node.operand)
            op = _UNARY_MAP.get(type(node.op), IROpcode.NEG)
            self._emit(op, dest=tmp, src1=operand)

        elif tp is ast.BoolOp:
            op = IROpcode.AND if isinstance(node.op, ast.And) else IROpcode.OR
            cur = self._visit_expr(node.values[0])
            for val in node.values[1:]:
                right = self._visit_expr(val)
                nxt   = self._new_tmp()
                self._emit(op, dest=nxt, src1=cur, src2=right)
                cur = nxt
            self._emit(IROpcode.ASSIGN, dest=tmp, src1=cur)

        elif tp is ast.Compare:
            left = self._visit_expr(node.left)
            cur  = left
            result = tmp
            for cmp_op, comparator in zip(node.ops, node.comparators):
                right = self._visit_expr(comparator)
                ir_op = _CMP_MAP.get(type(cmp_op), IROpcode.EQ)
                part  = self._new_tmp()
                self._emit(ir_op, dest=part, src1=cur, src2=right)
                cur = right
                result = part
            self._emit(IROpcode.ASSIGN, dest=tmp, src1=result)

        elif tp is ast.Call:
            func = self._visit_expr(node.func)
            args = [self._visit_expr(a) for a in node.args
                    if not isinstance(a, ast.Starred)]
            kwargs = {kw.arg: self._visit_expr(kw.value) for kw in node.keywords if kw.arg}
            starargs = [self._visit_expr(a.value) for a in node.args
                        if isinstance(a, ast.Starred)]
            self._emit(IROpcode.CALL, dest=tmp, src1=func,
                       meta={"args": args, "kwargs": kwargs, "starargs": starargs})

        elif tp is ast.Attribute:
            obj = self._visit_expr(node.value)
            self._emit(IROpcode.LOAD_ATTR, dest=tmp, src1=obj,
                       meta={"attr": node.attr})

        elif tp is ast.Subscript:
            obj = self._visit_expr(node.value)
            idx = self._visit_expr(node.slice)
            self._emit(IROpcode.LOAD_INDEX, dest=tmp, src1=obj, src2=idx)

        elif tp is ast.IfExp:
            cond = self._visit_expr(node.test)
            body = self._visit_expr(node.body)
            orelse = self._visit_expr(node.orelse)
            self._emit(IROpcode.CJUMP, src1=cond,
                       meta={"true": body, "false": orelse, "ternary": tmp})
            self._emit(IROpcode.ASSIGN, dest=tmp, src1=body)  # simplified

        elif tp is ast.List:
            items = [self._visit_expr(e) for e in node.elts]
            self._emit(IROpcode.BUILD_LIST, dest=tmp, meta={"items": items})

        elif tp is ast.Tuple:
            items = [self._visit_expr(e) for e in node.elts]
            self._emit(IROpcode.BUILD_TUPLE, dest=tmp, meta={"items": items})

        elif tp is ast.Set:
            items = [self._visit_expr(e) for e in node.elts]
            self._emit(IROpcode.BUILD_SET, dest=tmp, meta={"items": items})

        elif tp is ast.Dict:
            keys   = [self._visit_expr(k) if k else None for k in node.keys]
            values = [self._visit_expr(v) for v in node.values]
            self._emit(IROpcode.BUILD_DICT, dest=tmp,
                       meta={"keys": keys, "values": values})

        elif tp is ast.Yield:
            val = self._visit_expr(node.value) if node.value else None
            self._emit(IROpcode.YIELD, dest=tmp, src1=val)

        elif tp is ast.YieldFrom:
            val = self._visit_expr(node.value)
            self._emit(IROpcode.YIELD_FROM, dest=tmp, src1=val)

        elif tp is ast.Lambda:
            self._emit(IROpcode.MAKE_FUNCTION, dest=tmp,
                       meta={"name": "<lambda>", "ast_node": node})

        elif tp is ast.JoinedStr:  # f-string
            parts = [self._visit_expr(v) for v in node.values]
            self._emit(IROpcode.JOIN_STR, dest=tmp, meta={"parts": parts})

        elif tp is ast.FormattedValue:
            val = self._visit_expr(node.value)
            self._emit(IROpcode.FORMAT_VALUE, dest=tmp, src1=val,
                       meta={"conversion": node.conversion,
                              "format_spec": node.format_spec})

        elif tp is ast.Starred:
            val = self._visit_expr(node.value)
            self._emit(IROpcode.ASSIGN, dest=tmp, src1=val,
                       meta={"starred": True})

        elif tp is ast.NamedExpr:
            val = self._visit_expr(node.value)
            self._emit(IROpcode.ASSIGN, dest=tmp, src1=val)
            self._emit(IROpcode.STORE_NAME, dest=node.target.id, src1=tmp)

        elif tp is ast.Slice:
            lower = self._visit_expr(node.lower) if node.lower else None
            upper = self._visit_expr(node.upper) if node.upper else None
            step  = self._visit_expr(node.step)  if node.step  else None
            self._emit(IROpcode.BUILD_SLICE, dest=tmp,
                       src1=lower, src2=upper, meta={"step": step})

        else:
            # Fallback: store raw expression
            self._emit(IROpcode.LOAD_CONST, dest=tmp,
                       meta={"value": None, "raw_expr": node})

        return tmp

    # ── assignment helpers ────────────────────────────────────────────────────

    def _assign_target(self, target: ast.expr, src: str):
        if isinstance(target, ast.Name):
            self._emit(IROpcode.STORE_NAME, dest=target.id, src1=src)
        elif isinstance(target, ast.Attribute):
            obj = self._visit_expr(target.value)
            self._emit(IROpcode.STORE_ATTR, src1=obj, src2=src,
                       meta={"attr": target.attr})
        elif isinstance(target, ast.Subscript):
            obj = self._visit_expr(target.value)
            idx = self._visit_expr(target.slice)
            self._emit(IROpcode.STORE_INDEX, src1=obj, src2=idx,
                       meta={"value": src})
        elif isinstance(target, (ast.List, ast.Tuple)):
            tmp = self._new_tmp()
            self._emit(IROpcode.UNPACK_SEQ, dest=tmp, src1=src,
                       meta={"targets": [
                           t.id if isinstance(t, ast.Name) else ast.unparse(t)
                           for t in target.elts
                       ], "n": len(target.elts)})

    def _visit_augassign(self, node: ast.AugAssign):
        if isinstance(node.target, ast.Name):
            old = self._visit_expr(ast.Name(id=node.target.id))
            val = self._visit_expr(node.value)
            op  = _BINOP_MAP.get(type(node.op), IROpcode.ADD)
            tmp = self._new_tmp()
            self._emit(op, dest=tmp, src1=old, src2=val)
            self._emit(IROpcode.STORE_NAME, dest=node.target.id, src1=tmp)

    # ── imports ───────────────────────────────────────────────────────────────

    def _visit_import(self, node: ast.stmt):
        if isinstance(node, ast.Import):
            for alias in node.names:
                tmp = self._new_tmp()
                self._emit(IROpcode.IMPORT_NAME, dest=tmp,
                            meta={"module": alias.name})
                name = alias.asname or alias.name.split(".")[0]
                self._emit(IROpcode.STORE_NAME, dest=name, src1=tmp)
        elif isinstance(node, ast.ImportFrom):
            mod_tmp = self._new_tmp()
            self._emit(IROpcode.IMPORT_NAME, dest=mod_tmp,
                        meta={"module": node.module or ""})
            for alias in node.names:
                if alias.name == "*":
                    self._emit(IROpcode.IMPORT_STAR, src1=mod_tmp)
                else:
                    attr_tmp = self._new_tmp()
                    self._emit(IROpcode.IMPORT_FROM, dest=attr_tmp, src1=mod_tmp,
                                meta={"name": alias.name})
                    name = alias.asname or alias.name
                    self._emit(IROpcode.STORE_NAME, dest=name, src1=attr_tmp)

    # ── flat fallback ─────────────────────────────────────────────────────────

    def _wrap_flat(self, fn: IRFunction) -> CFG:
        cfg = CFG()
        blk = BasicBlock(label="entry")
        blk.instructions = fn.instructions
        cfg.add_block(blk)
        cfg.entry  = "entry"
        cfg.exit_  = "entry"
        return cfg


# ── operator maps ─────────────────────────────────────────────────────────────

_BINOP_MAP = {
    ast.Add:      IROpcode.ADD,
    ast.Sub:      IROpcode.SUB,
    ast.Mult:     IROpcode.MUL,
    ast.Div:      IROpcode.DIV,
    ast.FloorDiv: IROpcode.FLOOR_DIV,
    ast.Mod:      IROpcode.MOD,
    ast.Pow:      IROpcode.POW,
    ast.MatMult:  IROpcode.MATMUL,
    ast.BitAnd:   IROpcode.BAND,
    ast.BitOr:    IROpcode.BOR,
    ast.BitXor:   IROpcode.BXOR,
    ast.LShift:   IROpcode.LSHIFT,
    ast.RShift:   IROpcode.RSHIFT,
}

_UNARY_MAP = {
    ast.USub:   IROpcode.NEG,
    ast.UAdd:   IROpcode.POS,
    ast.Invert: IROpcode.BNOT,
    ast.Not:    IROpcode.NOT,
}

_CMP_MAP = {
    ast.Eq:    IROpcode.EQ,
    ast.NotEq: IROpcode.NE,
    ast.Lt:    IROpcode.LT,
    ast.LtE:   IROpcode.LE,
    ast.Gt:    IROpcode.GT,
    ast.GtE:   IROpcode.GE,
    ast.Is:    IROpcode.IS,
    ast.IsNot: IROpcode.IS_NOT,
    ast.In:    IROpcode.IN,
    ast.NotIn: IROpcode.NOT_IN,
}


# ── convenience ───────────────────────────────────────────────────────────────

def build_cfgs(module: IRModule) -> IRModule:
    builder = CFGBuilder()
    return builder.build_module(module)
