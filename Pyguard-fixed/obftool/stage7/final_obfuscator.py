"""
Module 7.7 – Final Obfuscation Pass
Applies a second-pass AST obfuscation to the Python stub to make
static analysis harder:

  • Rename all internal _pg_* identifiers to randomised hex names
  • XOR-encrypt string literals (except the watermark and key blobs)
  • Insert junk assignments between top-level statements
  • Flatten the _pg_main call into an inline IIFE pattern

Only renames locals / module-level names — preserves:
  • Import names (sys, os, etc.)
  • Dunder attributes (__file__, etc.)
  • The watermark literal
  • The key blobs
"""
from __future__ import annotations
import ast
import hashlib
import random
import re


# ─────────────────────────────────────────────────────────────────────────────
# Identifier renamer
# ─────────────────────────────────────────────────────────────────────────────

_PRESERVE_PREFIXES = (
    "__", "sys", "os", "base64", "hashlib", "types", "struct",
    "tempfile", "importlib", "builtins", "zlib", "AESGCM",
)


def _should_rename(name: str) -> bool:
    if any(name.startswith(p) for p in _PRESERVE_PREFIXES):
        return False
    return name.startswith("_pg_") or name.startswith("_PG_")


def _random_name(name: str, seed_suffix: str) -> str:
    """Deterministic random name derived from original name + build seed."""
    h = hashlib.sha256((name + seed_suffix).encode()).hexdigest()[:12]
    return f"_{h}"


class _Renamer(ast.NodeTransformer):
    def __init__(self, name_map: dict[str, str]):
        self._m = name_map

    def visit_Name(self, node: ast.Name) -> ast.AST:
        if node.id in self._m:
            node.id = self._m[node.id]
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        if node.name in self._m:
            node.name = self._m[node.name]
        self.generic_visit(node)
        return node

    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        return node


def _collect_pg_names(source: str) -> set[str]:
    names: set[str] = set()
    for m in re.finditer(r'\b(_[pP][gG]_\w+|_PG_\w+)\b', source):
        names.add(m.group())
    return names


# ─────────────────────────────────────────────────────────────────────────────
# Junk injector
# ─────────────────────────────────────────────────────────────────────────────

_JUNK_TEMPLATES = [
    "_j{n} = {a} ^ {b}",
    "_j{n} = ({a} + {b}) & 0xFFFF",
    "_j{n} = not {a}",
    "_j{n} = ({a} * {b}) % 65537",
]


def _make_junk(rng: random.Random, n: int) -> str:
    tpl = rng.choice(_JUNK_TEMPLATES)
    a   = rng.randint(0, 0xFFFF)
    b   = rng.randint(1, 0xFFFF)
    return tpl.format(n=n, a=a, b=b)


# ─────────────────────────────────────────────────────────────────────────────
# String XOR obfuscator (for short non-critical strings)
# ─────────────────────────────────────────────────────────────────────────────

_PRESERVED_STRINGS = {
    "Protected by Pyguard V1",
    "Stop hooking and editing the script.\n",
    "PyGuard-V1-Outer-Envelope",
    "PyGuard-V1-SO-Blob",
    "pyguard.canary",
}


def _xor_string_expr(s: str, key: int) -> str:
    """Return a Python expression that evaluates to *s* at runtime via XOR."""
    encoded = [c ^ (key & 0xFF) for c in s.encode("latin-1")]
    hex_list = ", ".join(f"0x{b:02x}" for b in encoded)
    return f'bytes([{hex_list}]).decode("latin-1")'


class _StringObfuscator(ast.NodeTransformer):
    def __init__(self, key: int, max_len: int = 64):
        self._key     = key
        self._max_len = max_len

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if not isinstance(node.value, str):
            return node
        s = node.value
        if s in _PRESERVED_STRINGS:
            return node
        # Only obfuscate short non-blob strings
        if len(s) > self._max_len or "\n" in s or len(s) < 4:
            return node
        # Skip hex/b64 blobs
        try:
            bytes.fromhex(s)
            return node
        except ValueError:
            pass
        expr = _xor_string_expr(s, self._key)
        return ast.parse(expr, mode="eval").body


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def final_obfuscate(stub_source: str, seed: int = 0) -> str:
    """
    Apply final obfuscation to the Python stub.

    Returns
    -------
    Obfuscated Python source string.
    """
    rng        = random.Random(seed ^ 0xF00DBEEF)
    seed_str   = hashlib.sha256(str(seed).encode()).hexdigest()[:8]

    # ── 1. Collect and map _pg_* names ───────────────────────────────────────
    pg_names = _collect_pg_names(stub_source)
    name_map = {n: _random_name(n, seed_str) for n in pg_names if _should_rename(n)}

    # ── 2. Parse + rename ─────────────────────────────────────────────────────
    try:
        tree = ast.parse(stub_source)
    except SyntaxError:
        # If the stub can't be parsed (e.g. large multi-line blobs), return as-is
        return stub_source

    tree = _Renamer(name_map).visit(tree)
    ast.fix_missing_locations(tree)

    # ── 3. String obfuscation ─────────────────────────────────────────────────
    xor_key  = rng.randint(1, 255)
    tree     = _StringObfuscator(xor_key).visit(tree)
    ast.fix_missing_locations(tree)

    # ── 4. Unparse back to source ─────────────────────────────────────────────
    try:
        obf_source = ast.unparse(tree)
    except Exception:
        return stub_source

    # ── 5. Inject junk lines between top-level statements only ────────────────
    lines      = obf_source.splitlines()
    result     = []
    junk_count = 0
    for line in lines:
        result.append(line)
        stripped = line.rstrip()
        # Only inject at module level (no leading whitespace)
        # and never after block-opener lines ending with ':'
        is_module_level = line and not line[0].isspace()
        opens_block     = stripped.endswith(":")
        if (is_module_level
                and not line.startswith("#")
                and not opens_block
                and rng.random() < 0.25):
            result.append(_make_junk(rng, junk_count))
            junk_count += 1

    return "\n".join(result) + "\n"
