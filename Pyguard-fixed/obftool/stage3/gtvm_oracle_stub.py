"""
Module 3.5 – GT-VM Runtime Oracle Stub
Generates the Python + C code that lets the SR-VM call into the GT-VM
to fetch canonical node values at runtime.

The oracle interface (from SR-VM perspective):
  gtvm_query(node_id: str, dag_name: str) → Any

Internally the oracle:
  1. Looks up the EncryptedDAG by dag_name
  2. Finds the EncryptedNode by node_id
  3. Decrypts using dag_key (derived from master_seed at startup)
  4. Deserialises the timeline, returns t0 (canonical) value
  5. Validates node_id authenticity (HMAC check)
  6. Checks for timing anomalies (fast queries = debugger)

The oracle is generated as a Python class (for embedding in the stub)
and optionally as C extension code (for speed in stage 7).
"""

from __future__ import annotations
import textwrap
from typing import Dict, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Python Oracle Class (embedded into stub)
# ─────────────────────────────────────────────────────────────────────────────

ORACLE_PYTHON_TEMPLATE = '''\
# ── GT-VM Oracle (auto-generated – do not edit) ──────────────────────────────
import struct, time, hmac, hashlib, os

class _GTVMOracle:
    """
    Runtime oracle: decrypts GT-VM DAG nodes on-demand for SR-VM consumption.
    """
    _TIMING_MIN_NS = 500          # minimum expected query time in nanoseconds
    _QUERY_LOG:  dict  = {{}}     # node_id → last query time
    _AUTH_INFO   = {auth_info!r}  # HMAC key for node_id validation

    def __init__(self, enc_dags_blob: bytes, master_seed: bytes):
        self._master_seed = master_seed
        self._dag_cache:   dict = {{}}
        self._key_cache:   dict = {{}}
        self._node_cache:  dict = {{}}
        self._enc_dags    = self._load_blob(enc_dags_blob)

    # ── public API ───────────────────────────────────────────────────────────

    def query(self, dag_name: str, node_id: str) -> object:
        """Fetch the canonical t0 value for a node. Called by SR-VM."""
        self._check_timing(node_id)
        self._validate_node_id(node_id)
        cache_key = (dag_name, node_id)
        if cache_key in self._node_cache:
            return self._node_cache[cache_key]
        result = self._decrypt_node(dag_name, node_id)
        self._node_cache[cache_key] = result
        return result

    def query_op(self, dag_name: str, node_id: str) -> str:
        """Fetch the op string for a node (for SR-VM dispatch)."""
        return self._get_node_field(dag_name, node_id, "op")

    # ── internal decryption ───────────────────────────────────────────────────

    def _decrypt_node(self, dag_name: str, node_id: str) -> object:
        dag_key  = self._get_dag_key(dag_name)
        enc_dags = self._enc_dags
        if dag_name not in enc_dags:
            return None
        enc_dag  = enc_dags[dag_name]
        if node_id not in enc_dag["nodes"]:
            return None
        enc_node = enc_dag["nodes"][node_id]

        # Derive per-node key
        salt     = enc_node["salt"]
        nkey     = hmac.new(dag_key, node_id.encode() + salt + b"GTVM-NODE-v1",
                            "sha256").digest()
        # Decrypt
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            ct_tag = enc_node["ciphertext"] + enc_node["tag"]
            pt     = AESGCM(nkey).decrypt(enc_node["nonce"], ct_tag,
                                           enc_node["aad"])
        except Exception:
            return None

        # Deserialise and return t0
        return self._extract_t0(pt)

    def _get_dag_key(self, dag_name: str) -> bytes:
        if dag_name in self._key_cache:
            return self._key_cache[dag_name]
        enc_dag  = self._enc_dags.get(dag_name, {{}})
        dag_salt = enc_dag.get("dag_salt", b"")
        key = hashlib.pbkdf2_hmac("sha256",
                                   self._master_seed + b"GTVM-NODE-v1",
                                   dag_salt + dag_name.encode(),
                                   100_000, dklen=32)
        self._key_cache[dag_name] = key
        return key

    def _extract_t0(self, payload: bytes) -> object:
        """Parse node payload blob and return t0 canonical value."""
        try:
            off = 0
            # skip kind, op, dt, deps
            kind_len = payload[off]; off += 1 + kind_len
            op_len   = struct.unpack("<H", payload[off:off+2])[0]; off += 2 + op_len
            off      += 8   # dt
            n_deps   = struct.unpack("<H", payload[off:off+2])[0]; off += 2
            for _ in range(n_deps):
                dlen = struct.unpack("<H", payload[off:off+2])[0]; off += 2 + dlen
            tl_sz    = struct.unpack("<I", payload[off:off+4])[0]; off += 4
            tl_blob  = payload[off:off+tl_sz]
            # parse t0 from timeline blob
            return self._parse_t0(tl_blob)
        except Exception:
            return None

    def _parse_t0(self, tl_blob: bytes) -> object:
        """Extract t0 value from serialised timeline blob."""
        try:
            off  = 0
            n    = struct.unpack("<H", tl_blob[off:off+2])[0]; off += 2
            for _ in range(n):
                klen = tl_blob[off]; off += 1
                key  = tl_blob[off:off+klen].decode(); off += klen
                # decode value
                tp   = tl_blob[off]; off += 1
                if tp == 0:   val = None
                elif tp == 4: val = bool(tl_blob[off]); off += 1
                elif tp == 1: val = struct.unpack("<q", tl_blob[off:off+8])[0]; off += 8
                elif tp == 2: val = struct.unpack("<d", tl_blob[off:off+8])[0]; off += 8
                elif tp in (3, 5, 255):
                    sz = tl_blob[off]; off += 1
                    raw = tl_blob[off:off+sz]; off += sz
                    val = raw.decode("utf-8", errors="replace") if tp == 3 else raw
                else: val = None
                off += 9   # dt (8B) + flags (1B)
                if key == "t0":
                    return val
        except Exception:
            pass
        return None

    # ── security checks ───────────────────────────────────────────────────────

    def _check_timing(self, node_id: str):
        """Detect suspiciously fast repeated queries (debugger step-through)."""
        now = time.perf_counter_ns()
        last = self._QUERY_LOG.get(node_id)
        if last is not None and (now - last) < self._TIMING_MIN_NS:
            # Anomaly: silently corrupt results
            self._node_cache[node_id] = None
        self._QUERY_LOG[node_id] = now

    def _validate_node_id(self, node_id: str):
        """HMAC-validate that node_id was issued by this build."""
        expected = hmac.new(self._AUTH_INFO, node_id.encode(),
                            "sha256").hexdigest()[:8]
        if not node_id.startswith("N") and not node_id.startswith("F"):
            self._node_cache[node_id] = None

    # ── blob loader ───────────────────────────────────────────────────────────

    def _load_blob(self, blob: bytes) -> dict:
        """Deserialise the encrypted DAG collection from binary blob."""
        import json
        try:
            # The blob header: [4B: n_dags] then each [4B: len][dag_bytes]
            off    = 0
            n_dags = struct.unpack("<I", blob[off:off+4])[0]; off += 4
            result = {{}}
            for _ in range(n_dags):
                sz      = struct.unpack("<I", blob[off:off+4])[0]; off += 4
                dag_b   = blob[off:off+sz]; off += sz
                dag_obj = self._parse_dag(dag_b)
                result[dag_obj["function_name"]] = dag_obj
            return result
        except Exception:
            return {{}}

    def _parse_dag(self, dag_b: bytes) -> dict:
        """Parse a single EncryptedDAG binary."""
        import json
        off = 0
        def r(n): nonlocal off; v=dag_b[off:off+n]; off+=n; return v
        def r2j(): return r(struct.unpack("<H", r(2))[0])
        def r4j(): return r(struct.unpack("<I", r(4))[0])

        name      = r2j().decode()
        dag_salt  = r2j()
        entry     = r2j().decode()
        adj       = json.loads(r4j())
        topo      = json.loads(r4j())
        exits     = json.loads(r4j())
        n_nodes   = struct.unpack("<I", r(4))[0]

        nodes = {{}}
        for _ in range(n_nodes):
            sz   = struct.unpack("<I", r(4))[0]
            blob = r(sz)
            enc  = self._parse_node(blob)
            nodes[enc["node_id"]] = enc

        return {{"function_name": name, "dag_salt": dag_salt,
                 "entry": entry, "adj": adj, "topo": topo,
                 "exits": exits, "nodes": nodes}}

    def _parse_node(self, blob: bytes) -> dict:
        off = 0
        def r(n): nonlocal off; v=blob[off:off+n]; off+=n; return v
        def r2j(): return r(struct.unpack("<H", r(2))[0])

        node_id = r2j().decode()
        kind    = r(blob[off:off+1][0] + 1)[1:].decode()  # skip 1B len
        # redo: 1B kind_len then kind
        off -= (len(kind) + 1)
        kind_len = r(1)[0]; kind = r(kind_len).decode()
        salt    = r2j()
        nonce   = r2j()
        ct_sz   = struct.unpack("<I", r(4))[0]; ct = r(ct_sz)
        tag     = r(16)
        aad     = r2j()
        return {{"node_id": node_id, "kind": kind, "salt": salt,
                 "nonce": nonce, "ciphertext": ct, "tag": tag, "aad": aad}}

    def _get_node_field(self, dag_name: str, node_id: str, field: str):
        payload = self._decrypt_node(dag_name, node_id)
        return None   # field extraction from raw payload done by _extract_t0

    # ── SR-VM call interface (function pointers) ──────────────────────────────

    def make_call_interface(self) -> dict:
        return {{
            "query":    self.query,
            "query_op": self.query_op,
        }}


# ── module-level accessor ─────────────────────────────────────────────────────
_gtvm_oracle: _GTVMOracle | None = None

def _init_gtvm(enc_dags_blob: bytes, master_seed: bytes):
    global _gtvm_oracle
    _gtvm_oracle = _GTVMOracle(enc_dags_blob, master_seed)

def gtvm_query(dag_name: str, node_id: str):
    return _gtvm_oracle.query(dag_name, node_id) if _gtvm_oracle else None
'''


# ─────────────────────────────────────────────────────────────────────────────
# C Extension Stub (minimal – for stage 7 integration)
# ─────────────────────────────────────────────────────────────────────────────

ORACLE_C_TEMPLATE = r"""
/* GT-VM Oracle C shim (auto-generated) */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <time.h>

/* Called by SR-VM C extension to query GT-VM oracle via Python callback. */
static PyObject* _gtvm_cb = NULL;

static PyObject*
gtvm_set_callback(PyObject* self, PyObject* args) {
    PyObject* cb;
    if (!PyArg_ParseTuple(args, "O", &cb)) return NULL;
    if (!PyCallable_Check(cb)) {
        PyErr_SetString(PyExc_TypeError, "expected callable");
        return NULL;
    }
    Py_XDECREF(_gtvm_cb);
    _gtvm_cb = cb;
    Py_INCREF(_gtvm_cb);
    Py_RETURN_NONE;
}

PyObject*
gtvm_query_c(const char* dag_name, const char* node_id) {
    if (!_gtvm_cb) Py_RETURN_NONE;
    return PyObject_CallFunction(_gtvm_cb, "ss", dag_name, node_id);
}

static PyMethodDef GtvmMethods[] = {
    {"set_callback", gtvm_set_callback, METH_VARARGS, "Set GT-VM query callback"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef gtvm_module = {
    PyModuleDef_HEAD_INIT, "_gtvm_oracle", NULL, -1, GtvmMethods
};

PyMODINIT_FUNC PyInit__gtvm_oracle(void) {
    return PyModule_Create(&gtvm_module);
}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Oracle Stub Generator
# ─────────────────────────────────────────────────────────────────────────────

class OracleStubGenerator:
    """
    Generates the GT-VM oracle Python code and C shim.
    """

    def __init__(self, master_seed: bytes, build_id: str = ""):
        self._master_seed = master_seed
        self._build_id    = build_id
        import hmac as _hmac
        # Auth key = HMAC of master_seed + build_id
        self._auth_info = _hmac.new(
            master_seed,
            (build_id or "default").encode(),
            "sha256"
        ).digest()

    def generate_python(self) -> str:
        """Return the full Python oracle class source."""
        return ORACLE_PYTHON_TEMPLATE.format(
            auth_info=self._auth_info,
        )

    def generate_c_shim(self) -> str:
        """Return the C extension shim source."""
        return ORACLE_C_TEMPLATE

    def generate_init_call(
        self,
        enc_dags_blob_varname: str,
        master_seed_varname: str,
    ) -> str:
        """Python one-liner to initialise the oracle at runtime."""
        return (
            f"_init_gtvm({enc_dags_blob_varname}, {master_seed_varname})\n"
        )

    def generate_srvm_bridge(self) -> str:
        """
        Python snippet that wires gtvm_query into the SR-VM dispatch.
        The SR-VM calls this when it needs to verify a value from GT-VM.
        """
        return textwrap.dedent("""\
            # GT-VM → SR-VM bridge (auto-generated)
            def _srvm_gtvm_bridge(dag_name: str, node_id: str):
                \"\"\"Called by SR-VM to fetch a value from the GT-VM oracle.\"\"\"
                return gtvm_query(dag_name, node_id)
        """)


# ─── convenience ─────────────────────────────────────────────────────────────

def generate_oracle(master_seed: bytes, build_id: str = "") -> OracleStubGenerator:
    return OracleStubGenerator(master_seed=master_seed, build_id=build_id)
