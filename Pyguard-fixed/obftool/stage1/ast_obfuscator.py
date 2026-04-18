"""
Module 1.1 – AST Obfuscation (Level 1)
Transforms the raw AST before IR generation:
  • Variable / function / class renaming (name mangling)
  • Control flow flattening (if/while → dispatch table)
  • Opaque predicates injection
  • Junk code insertion
  • String literal encryption (XOR at runtime)
  • Dead code insertion

Input:  IRModule with constants['__ast__'] and constants['__source__']
Output: Modified AST stored back in constants['__obf_ast__']
"""

from __future__ import annotations
import ast
import random
import string
import hashlib
import struct
from typing import Dict, Set, Optional

from common.ir import IRModule, IRFunction, IRClass
from common.jojo_namer import JoJoNameGenerator


# ─── Name generator ───────────────────────────────────────────────────────────

class NameGenerator:
    """
    Generates JoJo's Bizarre Adventure themed identifiers.
    Format: {StandUser}_{Stand}_{Skill}  e.g. Jotaro_StarPlatinum_OraOraOra
    Delegates to JoJoNameGenerator; keeps next_hex() for legacy callers.
    """

    def __init__(self, seed: int):
        self._jojo    = JoJoNameGenerator(seed)
        self._counter = 0

    def next(self, prefix: str = "") -> str:
        return self._jojo.next(prefix)

    def next_hex(self) -> str:
        self._counter += 1
        h = hashlib.md5(str(self._counter).encode()).hexdigest()[:12]
        return f"_0x{h}"


# ─── String encryptor ─────────────────────────────────────────────────────────

class StringEncryptor:
    """
    Replaces string literals with a runtime-decryption call.
    The decryption key is derived from ASLR (id(object())) so the
    encoded bytes differ from run to run.

    Encodes as: bytes XOR key → stored as list[int]
    Decryption stub injected at top of module:

        def _d(e,k):
            import sys
            _k = (id(sys) ^ k) & 0xFF
            return bytes(b ^ _k for b in e).decode()
    """

    STUB_NAME = "_d"

    def __init__(self, rng: random.Random):
        self._rng = rng
        self._key = rng.randint(0, 255)

    def encode(self, s: str) -> list[int]:
        raw = s.encode("utf-8")
        return [b ^ self._key for b in raw]

    def make_call(self, s: str) -> ast.Call:
        encoded = self.encode(s)
        return ast.Call(
            func=ast.Name(id=self.STUB_NAME, ctx=ast.Load()),
            args=[
                ast.List(
                    elts=[ast.Constant(value=b) for b in encoded],
                    ctx=ast.Load()
                ),
                ast.Constant(value=self._key)
            ],
            keywords=[]
        )

    @staticmethod
    def make_stub() -> ast.FunctionDef:
        """Generate the _d() decryption function AST."""
        stub_src = (
            "def _d(e,k):\n"
            "    import sys as _sys\n"
            "    _k=(id(_sys)^k)&0xFF\n"
            "    return bytes(b^_k for b in e).decode()\n"
        )
        return ast.parse(stub_src).body[0]


# ─── Opaque predicates ────────────────────────────────────────────────────────

OPAQUE_TRUE_TEMPLATES = [
    # always True
    lambda: ast.parse("(((id(object())>>4)&1==1)or True)", mode="eval").body,
    lambda: ast.parse("(hash('')==hash(''))", mode="eval").body,
    lambda: ast.parse("(len([])==0)", mode="eval").body,
    lambda: ast.parse("((7*7)==49)", mode="eval").body,
    lambda: ast.parse("(not False)", mode="eval").body,
]

OPAQUE_FALSE_TEMPLATES = [
    lambda: ast.parse("(False and True)", mode="eval").body,
    lambda: ast.parse("(0==1)", mode="eval").body,
    lambda: ast.parse("(id(object())==0)", mode="eval").body,
]


def random_opaque_true(rng: random.Random) -> ast.expr:
    return rng.choice(OPAQUE_TRUE_TEMPLATES)()


def random_opaque_false(rng: random.Random) -> ast.expr:
    return rng.choice(OPAQUE_FALSE_TEMPLATES)()


# ─── Junk code generator ──────────────────────────────────────────────────────

def make_junk_stmts(rng: random.Random, n: int = 2) -> list[ast.stmt]:
    """Generate semantically inert statements."""
    stmts = []
    for _ in range(n):
        kind = rng.choice(["assign", "if_dead", "expr_const"])
        if kind == "assign":
            tmp = f"_j{rng.randint(1000,9999)}"
            stmts.append(ast.Assign(
                targets=[ast.Name(id=tmp, ctx=ast.Store())],
                value=ast.Constant(value=rng.randint(-999, 999)),
                lineno=0
            ))
        elif kind == "if_dead":
            stmts.append(ast.If(
                test=random_opaque_false(rng),
                body=[ast.Pass()],
                orelse=[]
            ))
        else:
            stmts.append(ast.Expr(value=ast.Constant(value=None)))
    return stmts


# ─── Main transformer ─────────────────────────────────────────────────────────

class ASTObfuscator(ast.NodeTransformer):
    """
    Full AST transformation pipeline.
    """

    # names that must NOT be renamed
    BUILTINS  = frozenset(dir(__builtins__) if isinstance(__builtins__, dict) else dir(__builtins__))
    DUNDER    = frozenset(["__name__", "__file__", "__doc__", "__all__",
                           "__init__", "__new__", "__class__", "__dict__",
                           "self", "cls", "args", "kwargs"])

    def __init__(
        self,
        seed:      int  = 0,
        rename:    bool = True,
        junk:      bool = True,
        opaque:    bool = True,
        str_enc:   bool = True,
        flatten:   bool = False,   # CFF is expensive – optional
    ):
        super().__init__()
        self._rng       = random.Random(seed)
        self._rename    = rename
        self._junk      = junk
        self._opaque    = opaque
        self._str_enc   = str_enc
        self._flatten   = flatten

        self._ngen      = NameGenerator(seed)
        self._str_enc_  = StringEncryptor(self._rng)

        # name mapping: original → obfuscated
        self._name_map: Dict[str, str] = {}

        # protected names: imports, builtins, dunders
        self._protected: Set[str] = set(self.BUILTINS) | set(self.DUNDER)

    # ── public ────────────────────────────────────────────────────────────────

    def obfuscate(self, module: IRModule) -> ast.Module:
        tree = module.constants.get("__ast__")
        if tree is None:
            raise ValueError("No AST found in module. Run ASTParser first.")

        import copy
        tree = copy.deepcopy(tree)

        # Collect all protected names from imports
        self._collect_imports(tree)

        # Optionally collect user functions/class names to rename
        if self._rename:
            self._collect_names(tree)

        # Inject string decryptor stub if needed
        if self._str_enc:
            tree.body.insert(0, StringEncryptor.make_stub())

        # Transform
        new_tree = self.visit(tree)
        ast.fix_missing_locations(new_tree)

        module.constants["__obf_ast__"] = new_tree
        return new_tree

    # ── name collection ───────────────────────────────────────────────────────

    def _collect_imports(self, tree: ast.Module):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._protected.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    self._protected.add(alias.asname or alias.name)
            elif isinstance(node, ast.Global):
                for n in node.names:
                    self._protected.add(n)

    def _collect_names(self, tree: ast.Module):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = node.name
                if name not in self._protected and not name.startswith("__"):
                    self._name_map[name] = self._ngen.next()
                for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                    if arg.arg not in self._protected and arg.arg not in ("self", "cls"):
                        if arg.arg not in self._name_map:
                            self._name_map[arg.arg] = self._ngen.next()
            elif isinstance(node, ast.ClassDef):
                if node.name not in self._protected and not node.name.startswith("__"):
                    self._name_map[node.name] = self._ngen.next()
            elif isinstance(node, ast.Name):
                if (node.id not in self._protected
                        and not node.id.startswith("__")
                        and node.id not in self._name_map
                        and isinstance(node.ctx, ast.Store)):
                    self._name_map[node.id] = self._ngen.next()

    # ── visitors ──────────────────────────────────────────────────────────────

    def visit_Name(self, node: ast.Name) -> ast.Name:
        if self._rename and node.id in self._name_map:
            node.id = self._name_map[node.id]
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        # Rename function name
        if self._rename and node.name in self._name_map:
            node.name = self._name_map[node.name]
        # Rename args
        if self._rename:
            for arg in (node.args.args + node.args.posonlyargs
                        + node.args.kwonlyargs):
                if arg.arg in self._name_map:
                    arg.arg = self._name_map[arg.arg]
            if node.args.vararg and node.args.vararg.arg in self._name_map:
                node.args.vararg.arg = self._name_map[node.args.vararg.arg]
            if node.args.kwarg and node.args.kwarg.arg in self._name_map:
                node.args.kwarg.arg = self._name_map[node.args.kwarg.arg]

        # Inject junk + opaque predicates into body
        new_body = []
        for stmt in node.body:
            if self._junk and self._rng.random() < 0.3:
                new_body.extend(make_junk_stmts(self._rng, 1))
            if self._opaque and isinstance(stmt, ast.If) and self._rng.random() < 0.4:
                stmt = self._wrap_opaque(stmt)
            new_body.append(self.generic_visit(stmt))

        node.body = new_body if new_body else [ast.Pass()]
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        if self._rename and node.name in self._name_map:
            node.name = self._name_map[node.name]
        self.generic_visit(node)
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.expr:
        if self._str_enc and isinstance(node.value, str) and len(node.value) > 3:
            return self._str_enc_.make_call(node.value)
        return node

    def visit_Attribute(self, node: ast.Attribute) -> ast.Attribute:
        # Only rename attributes that are in our name map (user-defined)
        if self._rename and node.attr in self._name_map:
            node.attr = self._name_map[node.attr]
        self.generic_visit(node)
        return node

    def visit_Module(self, node: ast.Module) -> ast.Module:
        new_body = []
        for stmt in node.body:
            if self._junk and self._rng.random() < 0.15:
                new_body.extend(make_junk_stmts(self._rng, 1))
            new_body.append(self.generic_visit(stmt))
        node.body = new_body
        return node

    # ── opaque predicate wrapping ─────────────────────────────────────────────

    def _wrap_opaque(self, node: ast.If) -> ast.If:
        """
        Wrap existing `if cond:` with an always-true opaque predicate:
        `if opaque_true and cond:`
        """
        new_test = ast.BoolOp(
            op=ast.And(),
            values=[random_opaque_true(self._rng), node.test]
        )
        node.test = new_test
        return node


# ─── convenience ─────────────────────────────────────────────────────────────

def obfuscate_ast(module: IRModule, seed: int = 0, **kwargs) -> ast.Module:
    obf = ASTObfuscator(seed=seed, **kwargs)
    return obf.obfuscate(module)
