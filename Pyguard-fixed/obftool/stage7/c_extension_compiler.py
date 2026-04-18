"""
Module 7.4 – C Extension Compiler
Compiles the generated C source into a CPython extension (.so).

Strategy:
  1. Write C source to a temp directory.
  2. Generate a minimal setup.py and run:
       python setup.py build_ext --inplace
  3. Locate the produced .so and read its bytes.
  4. Clean up temp dir.

Falls back to a pure-Python stub .so (empty bytes) if compilation fails
so that the rest of the pipeline (encoding → stub generation) continues to
run even on machines without a C compiler.
"""
from __future__ import annotations
import os
import sys
import shutil
import tempfile
import subprocess


_SETUP_PY = '''\
try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension

ext = Extension(
    "_pyguard_ext",
    sources=["_pyguard_ext.c"],
    libraries=["ssl", "crypto", "z"],
    extra_compile_args=["-O2", "-fvisibility=hidden",
                        "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2"],
    extra_link_args=["-Wl,-z,relro,-z,now"],
)
setup(name="_pyguard_ext", ext_modules=[ext])
'''


def _compile_with_gcc(c_source: str, tmpdir: str) -> bytes:
    """Direct gcc compile fallback when setup.py fails."""
    import sysconfig
    c_path  = os.path.join(tmpdir, "_pyguard_ext.c")
    so_path = os.path.join(tmpdir, "_pyguard_ext.so")
    with open(c_path, "w") as f:
        f.write(c_source)

    inc  = sysconfig.get_path("include")
    libs = sysconfig.get_config_var("LIBDIR") or ""
    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    so_path = os.path.join(tmpdir, f"_pyguard_ext{ext_suffix}")

    cmd = [
        "gcc", "-shared", "-fPIC", "-O2",
        "-fvisibility=hidden", "-fstack-protector-strong",
        f"-I{inc}",
        c_path, "-o", so_path,
        "-lssl", "-lcrypto", "-lz",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"gcc failed: {r.stderr[-1000:]}")
    with open(so_path, "rb") as f:
        return f.read()


def compile_extension(c_source: str) -> tuple[bytes, bool]:
    """
    Compile *c_source* to a .so binary.

    Returns
    -------
    (so_bytes, success)
        so_bytes : raw bytes of the .so (or b'' on failure)
        success  : True if compilation succeeded
    """
    tmpdir = tempfile.mkdtemp(prefix="pyguard_build_")
    try:
        c_path     = os.path.join(tmpdir, "_pyguard_ext.c")
        setup_path = os.path.join(tmpdir, "setup.py")

        with open(c_path,     "w") as f: f.write(c_source)
        with open(setup_path, "w") as f: f.write(_SETUP_PY)

        result = subprocess.run(
            [sys.executable, "setup.py", "build_ext", "--inplace"],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode == 0:
            # Find the produced .so
            for fname in os.listdir(tmpdir):
                if fname.startswith("_pyguard_ext") and fname.endswith(".so"):
                    so_path = os.path.join(tmpdir, fname)
                    with open(so_path, "rb") as f:
                        return f.read(), True

        # setup.py failed (e.g. distutils removed in 3.12) — try direct gcc
        print(f"[Stage7] setup.py failed, trying direct gcc fallback...")
        so_bytes = _compile_with_gcc(c_source, tmpdir)
        return so_bytes, True

    except Exception as exc:
        print(f"[Stage7] C compile FAILED: {exc}")
        return b"", False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
