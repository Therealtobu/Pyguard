"""
Stage 7 – Packing & Loader Generation

Public API
----------
build_stage7(R, out_dir, build_id, seed, verbose) → str
    Full stage 7 pipeline. Returns final stub source.
"""
from __future__ import annotations
import os

from stage7.payload_packer      import pack_payload
from stage7.compression_outer   import derive_outer_key, compress_and_encrypt
from stage7.c_extension_builder import build_c_extension_source
from stage7.c_extension_compiler import compile_extension
from stage7.c_extension_encoder  import (
    encrypt_and_encode_so, encode_payload, chunk_b64
)
from stage7.stub_generator      import generate_stub, finalise_integrity_hash
from stage7.final_obfuscator    import final_obfuscate


def build_stage7(
    R:        dict,
    out_dir:  str,
    build_id: str,
    seed:     int  = 0,
    verbose:  bool = True,
) -> str:
    """
    Run all Stage 7 modules and write `obfuscated_final.py` to *out_dir*.

    Parameters
    ----------
    R        : pipeline result dict from stages 0–6
    out_dir  : output directory (already exists)
    build_id : short build fingerprint
    seed     : integer seed for determinism
    verbose  : print progress

    Returns
    -------
    Path to the generated `obfuscated_final.py`.
    """
    def log(m):
        if verbose: print(f"     {m}")

    # ── 7.1 Pack payload ──────────────────────────────────────────────────────
    log("7.1 Payload Packer")
    exec_graph = R["exec_graph"]
    packed = pack_payload(
        graph_blob      = R["graph_blob"],
        srvm_bundle     = R["srvm_bundle"],
        gtvm_bundle     = R["gtvm_bundle"],
        native_bundle   = R["native_bundle"],
        wd_bundle       = R["wd_bundle"],
        interleave_seed = exec_graph.interleave_seed,
        build_id        = build_id,
    )
    log(f"     packed payload: {packed.total_size:,} bytes")

    # ── 7.2 Compress + outer encrypt ─────────────────────────────────────────
    log("7.2 Compress & Outer Encrypt")
    outer_key = derive_outer_key(R["graph_master_key"], R["bc_seed"])
    envelope  = compress_and_encrypt(packed.serialise(), outer_key)
    log(f"     envelope: {envelope.total_size:,} bytes")

    # ── 7.3 Build C extension source ─────────────────────────────────────────
    log("7.3 C Extension Builder")
    c_source = build_c_extension_source()
    log(f"     C source: {len(c_source):,} chars")

    # ── 7.4 Compile C extension ───────────────────────────────────────────────
    log("7.4 C Extension Compiler")
    so_bytes, compile_ok = compile_extension(c_source)
    if compile_ok:
        log(f"     .so: {len(so_bytes):,} bytes")
    else:
        log("     compile failed – using Python fallback loader")

    # ── 7.5 Encode blobs ─────────────────────────────────────────────────────
    log("7.5 C Extension Encoder")
    if so_bytes:
        so_b64, so_key_hex = encrypt_and_encode_so(so_bytes, R["graph_master_key"])
    else:
        so_b64, so_key_hex = "", ""

    payload_b64 = encode_payload(envelope.serialise())
    pl_key_hex  = outer_key.hex()
    log(f"     SO b64: {len(so_b64):,} chars | payload b64: {len(payload_b64):,} chars")

    # ── 7.6 Generate Python stub ──────────────────────────────────────────────
    log("7.6 Python Stub Generator")
    stub_source = generate_stub(
        so_b64      = so_b64,
        so_key_hex  = so_key_hex,
        payload_b64 = payload_b64,
        pl_key_hex  = pl_key_hex,
    )
    log(f"     stub: {len(stub_source):,} chars")

    # ── 7.7 Final obfuscation ─────────────────────────────────────────────────
    log("7.7 Final Obfuscation Pass")
    final_source = final_obfuscate(stub_source, seed=seed)
    log(f"     final: {len(final_source):,} chars")

    # ── 7.8 Finalise integrity hash (Fix B+C) ────────────────────────────────
    # Must run AFTER final_obfuscate so the hash covers the actual obfuscated
    # source that _pg_check_integrity() will verify at runtime via _PG_S7.
    log("7.8 Finalise Integrity Hash")
    final_source = finalise_integrity_hash(final_source)
    stage7_bytes = final_source.encode("utf-8")
    log(f"     integrity hash embedded; stage7 size: {len(stage7_bytes):,} bytes")

    # ── Write output ──────────────────────────────────────────────────────────
    out_path = os.path.join(out_dir, "obfuscated_final.py")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(final_source)
    log(f"     → {out_path}")

    # ── Save C source for inspection ──────────────────────────────────────────
    with open(os.path.join(out_dir, "_pyguard_ext.c"), "w") as f:
        f.write(c_source)

    return out_path, stage7_bytes
