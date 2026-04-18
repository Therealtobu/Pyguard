"""
Module 0.1 – AST Parser
Parses Python source code into an AST and extracts structural metadata:
functions, classes, imports, constants, and top-level statements.
"""

from __future__ import annotations
import ast
import textwrap
from typing import Optional
from common.ir import IRModule, IRFunction, IRClass


# ─── helpers ──────────────────────────────────────────────────────────────────

def _arg_names(args: ast.arguments) -> list[str]:
    names = [a.arg for a in args.args]
    if args.vararg:
        names.append(f"*{args.vararg.arg}")
    if args.kwonlyargs:
        names.extend(a.arg for a in args.kwonlyargs)
    if args.kwarg:
        names.append(f"**{args.kwarg.arg}")
    return names


def _decorator_names(decorator_list: list[ast.expr]) -> list[str]:
    names = []
    for d in decorator_list:
        if isinstance(d, ast.Name):
            names.append(d.id)
        elif isinstance(d, ast.Attribute):
            names.append(ast.unparse(d))
        elif isinstance(d, ast.Call):
            names.append(ast.unparse(d))
        else:
            names.append("<unknown>")
    return names


def _constant_value(node: ast.expr):
    """Extract constant value from AST node, return None if not constant."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        if isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, (int, float)):
            return -node.operand.value
    return None


# ─── main parser class ────────────────────────────────────────────────────────

class ASTParser:
    """
    Parses a Python source file and populates an IRModule with:
    - Function stubs (name, args, decorators)
    - Class stubs (name, bases, methods)
    - Module-level import list
    - Module-level constant assignments
    - Raw AST tree (stored in module.constants['__ast__'])
    """

    def __init__(self, source: str, filename: str = "<unknown>"):
        self.source   = source
        self.filename = filename
        self._tmp_counter = 0

    # ── public API ────────────────────────────────────────────────────────────

    def parse(self) -> IRModule:
        try:
            tree = ast.parse(self.source, filename=self.filename)
        except SyntaxError as e:
            raise ValueError(f"Syntax error in {self.filename}: {e}") from e

        module = IRModule(
            name=self.filename.replace(".py", "").replace("/", "."),
            source_file=self.filename,
        )
        module.constants["__ast__"] = tree
        module.constants["__source__"] = self.source

        self._walk_module(tree, module)
        return module

    # ── module-level walk ─────────────────────────────────────────────────────

    def _walk_module(self, tree: ast.Module, module: IRModule):
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self._handle_import(node, module)
            elif isinstance(node, ast.FunctionDef):
                fn = self._parse_function(node)
                module.functions[fn.name] = fn
            elif isinstance(node, ast.AsyncFunctionDef):
                fn = self._parse_function(node, is_async=True)
                module.functions[fn.name] = fn
            elif isinstance(node, ast.ClassDef):
                cls = self._parse_class(node)
                module.classes[cls.name] = cls
            elif isinstance(node, ast.Assign):
                self._handle_module_assign(node, module)
            elif isinstance(node, ast.AnnAssign):
                self._handle_ann_assign(node, module)
            # All raw nodes are stored for later TAC generation
            module.module_instrs  # will be populated by tac_generator

    # ── imports ───────────────────────────────────────────────────────────────

    def _handle_import(self, node: ast.stmt, module: IRModule):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module.imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            pkg = node.module or ""
            for alias in node.names:
                module.imports.append(f"{pkg}.{alias.name}" if pkg else alias.name)

    # ── functions ────────────────────────────────────────────────────────────

    def _parse_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        is_async: bool = False,
    ) -> IRFunction:
        args = _arg_names(node.args)
        vararg = node.args.vararg.arg if node.args.vararg else None
        kwarg  = node.args.kwarg.arg  if node.args.kwarg  else None

        # default values
        defaults: dict = {}
        arg_names_plain = [a.arg for a in node.args.args]
        n_defaults = len(node.args.defaults)
        if n_defaults:
            offset = len(arg_names_plain) - n_defaults
            for i, dflt in enumerate(node.args.defaults):
                v = _constant_value(dflt)
                if v is not None:
                    defaults[arg_names_plain[offset + i]] = v

        fn = IRFunction(
            name=node.name,
            args=args,
            varargs=vararg,
            kwargs=kwarg,
            defaults=defaults,
            is_generator=isinstance(node, ast.FunctionDef) and self._is_generator(node),
            is_async=is_async,
            decorators=_decorator_names(node.decorator_list),
        )

        # Collect local variable names (naive scan)
        fn.locals_ = self._collect_locals(node)

        # Collect globals/nonlocals
        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                fn.globals_used.extend(child.names)

        # Recursively parse nested functions
        for child in node.body:
            if isinstance(child, ast.FunctionDef):
                nested = self._parse_function(child)
                fn.nested[nested.name] = nested
            elif isinstance(child, ast.AsyncFunctionDef):
                nested = self._parse_function(child, is_async=True)
                fn.nested[nested.name] = nested
            elif isinstance(child, ast.ClassDef):
                # nested class – store as metadata
                fn.nested[child.name] = self._parse_class_as_fn(child)

        # Store raw AST for later TAC generation
        fn.constants["__ast_node__"] = node
        return fn

    def _is_generator(self, node: ast.FunctionDef) -> bool:
        for child in ast.walk(node):
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                return True
        return False

    def _collect_locals(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        """Statically collect names assigned inside a function body."""
        locals_: set[str] = set()
        arg_names = {a.arg for a in node.args.args}
        if node.args.vararg:
            arg_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            arg_names.add(node.args.kwarg.arg)

        globals_decl: set[str] = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                globals_decl.update(child.names)
            elif isinstance(child, ast.Assign):
                for t in child.targets:
                    if isinstance(t, ast.Name):
                        locals_.add(t.id)
            elif isinstance(child, ast.AnnAssign):
                if isinstance(child.target, ast.Name):
                    locals_.add(child.target.id)
            elif isinstance(child, ast.AugAssign):
                if isinstance(child.target, ast.Name):
                    locals_.add(child.target.id)
            elif isinstance(child, ast.For):
                if isinstance(child.target, ast.Name):
                    locals_.add(child.target.id)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                for alias in child.names:
                    name = alias.asname or (alias.name.split(".")[0])
                    locals_.add(name)
            elif isinstance(child, ast.NamedExpr):
                locals_.add(child.target.id)

        return list((locals_ | arg_names) - globals_decl)

    # ── classes ──────────────────────────────────────────────────────────────

    def _parse_class(self, node: ast.ClassDef) -> IRClass:
        bases = [ast.unparse(b) for b in node.bases]
        cls = IRClass(
            name=node.name,
            bases=bases,
            decorators=_decorator_names(node.decorator_list),
        )
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                method = self._parse_function(item)
                method.is_method = True
                cls.methods[method.name] = method
            elif isinstance(item, ast.AsyncFunctionDef):
                method = self._parse_function(item, is_async=True)
                method.is_method = True
                cls.methods[method.name] = method
            elif isinstance(item, ast.Assign):
                for t in item.targets:
                    if isinstance(t, ast.Name):
                        v = _constant_value(item.value)
                        cls.attrs[t.id] = v
        cls.attrs["__ast_node__"] = node
        return cls

    def _parse_class_as_fn(self, node: ast.ClassDef) -> IRFunction:
        """Represent a nested class as a minimal IRFunction (for storage in fn.nested)."""
        fn = IRFunction(name=node.name)
        fn.constants["__ast_node__"] = node
        fn.constants["__is_class__"] = True
        return fn

    # ── module-level constants ────────────────────────────────────────────────

    def _handle_module_assign(self, node: ast.Assign, module: IRModule):
        for target in node.targets:
            if isinstance(target, ast.Name):
                v = _constant_value(node.value)
                if v is not None:
                    module.constants[target.id] = v

    def _handle_ann_assign(self, node: ast.AnnAssign, module: IRModule):
        if isinstance(node.target, ast.Name) and node.value is not None:
            v = _constant_value(node.value)
            if v is not None:
                module.constants[node.target.id] = v


# ─── convenience function ─────────────────────────────────────────────────────

def parse_source(source: str, filename: str = "<stdin>") -> IRModule:
    """Parse Python source string into an IRModule."""
    parser = ASTParser(source, filename)
    return parser.parse()


def parse_file(path: str) -> IRModule:
    """Parse a .py file into an IRModule."""
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()
    return parse_source(source, filename=path)


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, json

    if len(sys.argv) < 2:
        print("Usage: python -m stage0.ast_parser <file.py>")
        sys.exit(1)

    module = parse_file(sys.argv[1])
    print(f"Module : {module.name}")
    print(f"Imports: {module.imports}")
    print(f"Functions ({len(module.functions)}):")
    for name, fn in module.functions.items():
        print(f"  {name}({', '.join(fn.args)})  locals={fn.locals_}")
    print(f"Classes ({len(module.classes)}):")
    for name, cls in module.classes.items():
        print(f"  class {name}({', '.join(cls.bases)})  methods={list(cls.methods)}")
    print(f"Constants: {list(k for k in module.constants if not k.startswith('__'))}")
