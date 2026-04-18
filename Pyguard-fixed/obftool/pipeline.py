"""
ObfTool – Stage 0→6 Pipeline Runner
Usage:
    python pipeline.py <input.py> [--seed 1234] [--out ./build]
"""
from __future__ import annotations
import os, sys, time, argparse, hashlib, json, struct
sys.path.insert(0, os.path.dirname(__file__))

from stage0 import parse_source, build_cfgs, analyze, profile
from stage1 import (obfuscate_ast, generate_tac, duplicate_ir, mutate_ir,
                    apply_cff, apply_mba_transform, encrypt_strings)
from stage2 import (build_runtime_dispatch, compile_module,
                    encrypt_bytecodes, build_metadata, BytecodeEncryptor)
from stage3 import (build_dags, generate_timelines, inject_fake_timelines,
                    encrypt_dags, generate_oracle)
from stage4 import (select_hot_paths, generate_llvm_ir, compile_and_encrypt)
from stage5 import build_watchdog
from stage6 import (Fragmenter, StatefulInterleaver, TagGenerator,
                    build_execution_graph)
from stage7 import build_stage7
from stage8 import wrap as wrap_stage8


def _gtvm_bundle(encrypted_dags: dict) -> bytes:
    pieces = [struct.pack('<I', len(encrypted_dags))]
    for enc in encrypted_dags.values():
        blob = enc.serialise()
        pieces += [struct.pack('<I', len(blob)), blob]
    return b"".join(pieces)


def run_pipeline(source, filename="<stdin>", seed=0, out_dir="./build", verbose=True):
    os.makedirs(out_dir, exist_ok=True)
    t0 = time.perf_counter()
    def log(m):
        if verbose: print(f"  [{time.perf_counter()-t0:5.2f}s] {m}")
    R = {}

    # ── STAGE 0 ──────────────────────────────────────────────────────────────
    log("── STAGE 0 ────────────────────────────────────────────────")
    log("0.1 AST Parser");        module = parse_source(source, filename)
    log("0.2 CFG Builder");       build_cfgs(module)
    log("0.3 Data Dep Analysis"); analyze(module)
    log("0.4 Static Profiler");   prof = profile(module)
    if verbose: print(prof.summary())
    R["module"] = module

    log("── STAGE 1 ────────────────────────────────────────────────")
    log("1.1 AST Obfuscation")
    module.constants["__obf_ast__"] = obfuscate_ast(module, seed=seed)
    log("1.2 TAC IR Generation"); generate_tac(module)

    # ── NEW: String encryption before CFF (encrypts literals before obfuscation) ──
    log("1.2a String/Constant Encryption")
    encrypt_strings(module, seed=seed, encrypt_strings=True,
                    encrypt_bytes_lits=True, intensity=1.0)

    # ── NEW: CFF pass (hash-chain state machine, fake edges, data coupling) ──
    log("1.2b Control Flow Flattening (CFF)")
    module, _cff_state_var = apply_cff(
        module, seed=seed,
        n_fake_blocks=4,
        data_coupling=True,
        mba_transitions=True,
        deep_state=True,
    )

    # ── NEW: MBA v2 pass (deep chains, state coupling, non-linear) ───────────
    log("1.2c MBA Transform v2 (deep chains + state coupling)")
    apply_mba_transform(
        module, seed=seed,
        intensity=0.80,
        state_var=_cff_state_var,
        use_state_coupling=True,
    )

    log("1.3 IR Duplication");    ir_main, ir_shadow = duplicate_ir(module)
    log("1.4 IR Mutation");       ir_main, ir_shadow = mutate_ir(ir_main, ir_shadow, seed=seed)
    R.update(ir_main=ir_main, ir_shadow=ir_shadow)

    # ── STAGE 2 ──────────────────────────────────────────────────────────────
    log("── STAGE 2 ────────────────────────────────────────────────")
    log("2.2 Runtime Poly Dispatch"); dispatch = build_runtime_dispatch()
    if verbose:
        for l in dispatch.debug_info().split("\n")[:4]: print(f"     {l}")
    log("2.1 SR-VM Compile");       bytecodes = compile_module(ir_main, dispatch)
    log("2.3 Bytecode Encrypt")
    bc_seed = os.urandom(32)
    encrypted_bc, bc_seed = encrypt_bytecodes(bytecodes, seed=bc_seed)
    log("2.4 Metadata Builder")
    build_id = hashlib.sha256(source.encode()).hexdigest()[:16]
    srvm_meta, srvm_header = build_metadata(
        module_name=module.name, bytecodes=bytecodes, encrypted=encrypted_bc,
        dispatch_seed=dispatch.serialise_seed(), build_salt=bc_seed[:16],
        ir_module=ir_main, build_id=build_id)
    enc_obj     = BytecodeEncryptor.from_seed(bc_seed)
    srvm_bundle = enc_obj.serialise_bundle(encrypted_bc)
    log(f"     {len(bytecodes)} fns | {len(srvm_bundle):,} bytes")
    R.update(dispatch=dispatch, bytecodes=bytecodes, bc_seed=bc_seed,
             srvm_meta=srvm_meta, srvm_header=srvm_header, srvm_bundle=srvm_bundle)

    # ── STAGE 3 ──────────────────────────────────────────────────────────────
    log("── STAGE 3 ────────────────────────────────────────────────")
    log("3.1 GT-VM DAG Build");    dags = build_dags(ir_shadow)
    log("3.2 Timeline Gen");       dags = generate_timelines(dags, seed=seed)
    log("3.4 Fake Inject");        dags = inject_fake_timelines(dags, seed=seed+1)
    log("3.3 GT-VM Encrypt")
    gtvm_seed = os.urandom(32)
    encrypted_dags, gtvm_seed = encrypt_dags(dags, master_seed=gtvm_seed)
    log("3.5 Oracle Stub")
    oracle_gen    = generate_oracle(master_seed=gtvm_seed, build_id=build_id)
    oracle_py     = oracle_gen.generate_python()
    oracle_c      = oracle_gen.generate_c_shim()
    gtvm_bundle   = _gtvm_bundle(encrypted_dags)
    n_nodes = sum(len(d.nodes) for d in dags.values())
    log(f"     {len(dags)} DAGs | {n_nodes:,} nodes | {len(gtvm_bundle):,} bytes")
    R.update(dags=dags, encrypted_dags=encrypted_dags, gtvm_seed=gtvm_seed,
             gtvm_bundle=gtvm_bundle, oracle_py=oracle_py, oracle_c=oracle_c)

    # ── STAGE 4 ──────────────────────────────────────────────────────────────
    log("── STAGE 4 ────────────────────────────────────────────────")
    log("4.1 Hot Path Select")
    hot_report = select_hot_paths(ir_main)
    if verbose: print(hot_report.summary())
    log("4.2 LLVM IR Gen")
    fn_irs, module_ir = generate_llvm_ir(ir_main, hot_report, seed=seed)
    log("4.3-4.6 Compile→Extract→Split→Encrypt")
    native_seed = os.urandom(32)
    enc_native, native_seed, native_bundle = compile_and_encrypt(
        fn_irs=fn_irs, seed=native_seed, split_seed=seed)
    n_blocks = sum(len(v) for v in enc_native.values())
    log(f"     {len(fn_irs)} fns | {n_blocks} blocks | {len(native_bundle):,} bytes")
    R.update(hot_report=hot_report, fn_irs=fn_irs, module_ir=module_ir,
             enc_native=enc_native, native_seed=native_seed, native_bundle=native_bundle)

    # ── STAGE 5 ──────────────────────────────────────────────────────────────
    log("── STAGE 5 ────────────────────────────────────────────────")
    log("5.1-5.4 Watchdog Gen→Compile→Embed")
    wd_c, wd_so, wd_bundle = build_watchdog(seed=seed, poll_ms=250)
    log(f"     C: {len(wd_c):,} chars | .so: {len(wd_so):,} bytes | bundle: {len(wd_bundle):,} bytes")
    R.update(wd_c=wd_c, wd_so=wd_so, wd_bundle=wd_bundle)

    # ── STAGE 6 ──────────────────────────────────────────────────────────────
    log("── STAGE 6 ────────────────────────────────────────────────")
    log("6.1 Fragmenter")
    fragmenter = Fragmenter(seed=seed)
    frag_pool  = fragmenter.fragment_all(
        srvm_bundle=srvm_bundle, gtvm_bundle=gtvm_bundle,
        native_bundle=native_bundle, wd_bundle=wd_bundle, junk_ratio=0.40)
    if verbose: print(frag_pool.stats())

    log("6.2 Stateful Interleaver")
    interleaver     = StatefulInterleaver(seed=seed ^ 0xCAFEBABE)
    ordered_frags   = interleaver.interleave(frag_pool)
    interleave_seed = interleaver.seed

    log("6.3 Tag Generator")
    global_tag_seed = seed ^ 0xFEEDF00D
    tag_gen         = TagGenerator(global_tag_seed)
    tagged_frags    = tag_gen.tag_sequence(ordered_frags)
    tag_table       = tag_gen.serialise_tag_table(tagged_frags)

    log("6.4-6.5 Execution Graph + Per-Node Keys")
    graph_master_key = hashlib.pbkdf2_hmac(
        "sha256", gtvm_seed + native_seed + bc_seed,
        b"EXECGRAPH-MASTER", 100_000, dklen=32)
    exec_graph, graph_blob = build_execution_graph(
        tagged=tagged_frags, interleave_seed=interleave_seed,
        global_tag_seed=global_tag_seed, master_key=graph_master_key)
    log(exec_graph.stats())
    log(f"     Graph blob: {len(graph_blob):,} bytes")
    R.update(frag_pool=frag_pool, ordered_frags=ordered_frags,
             tagged_frags=tagged_frags, exec_graph=exec_graph,
             graph_blob=graph_blob, graph_master_key=graph_master_key)

    # ── STAGE 7 ──────────────────────────────────────────────────────────────
    log("── STAGE 7 ────────────────────────────────────────────────")
    log("7.1-7.8 Pack → Encrypt → C Ext → Stub → Obfuscate → Hash")
    final_py, _s7_bytes = build_stage7(R, out_dir, build_id, seed=seed, verbose=verbose)
    log(f"     Output: {final_py}")

    # ── STAGE 8 ──────────────────────────────────────────────────────────────
    log("── STAGE 8 ────────────────────────────────────────────────")
    log("8.1 Outer VM+Native Encryption Wrapper")
    import pathlib
    _s7_src  = _s7_bytes.decode("utf-8")   # already in memory — no re-read needed
    _s8_src  = wrap_stage8(_s7_src, seed=seed)
    _s8_path = pathlib.Path(out_dir) / "obfuscated_final.py"
    _s8_path.write_text(_s8_src, encoding="utf-8")
    log(f"     Stage 8 output: {len(_s8_src):,} chars → {_s8_path}")
    R["final_py"] = str(_s8_path)

    # ── Save artifacts ────────────────────────────────────────────────────────
    _save(R, out_dir, build_id, verbose)
    elapsed = time.perf_counter() - t0
    _summary(R, elapsed, verbose)
    return R


def _save(R, out_dir, build_id, verbose):
    def w(n, d, m="wb"): open(os.path.join(out_dir,n),m).write(d)
    w("srvm_header.bin",  R["srvm_header"])
    w("srvm_bundle.bin",  R["srvm_bundle"])
    w("gtvm_bundle.bin",  R["gtvm_bundle"])
    w("native_bundle.bin",R["native_bundle"])
    w("wd_bundle.bin",    R["wd_bundle"])
    w("graph_blob.bin",   R["graph_blob"])
    w("gtvm_oracle.py",   R["oracle_py"],"w")
    w("gtvm_oracle.c",    R["oracle_c"], "w")
    w("watchdog.c",       R["wd_c"],     "w")
    if R.get("module_ir"): w("hot_fns.ll", R["module_ir"], "w")
    g = R["exec_graph"]
    seeds = {
        "build_id": build_id, "bc_seed": R["bc_seed"].hex(),
        "gtvm_seed": R["gtvm_seed"].hex(), "native_seed": R["native_seed"].hex(),
        "dispatch_seed": R["dispatch"].serialise_seed().hex(),
        "graph_master_key": R["graph_master_key"].hex(),
        "interleave_seed": g.interleave_seed,
        "global_tag_seed": g.global_tag_seed,
    }
    w("seeds.json", json.dumps(seeds, indent=2), "w")
    if verbose:
        print(f"\n  Artifacts → {out_dir}/")
        for f in sorted(os.listdir(out_dir)):
            sz = os.path.getsize(os.path.join(out_dir, f))
            print(f"    {f:<28} {sz:>10,} bytes")


def _summary(R, elapsed, verbose):
    if not verbose: return
    g = R["exec_graph"]
    n_edges = sum(len(n.successors) for n in g.nodes.values())
    tot = sum(len(R[k]) for k in ("srvm_bundle","gtvm_bundle","native_bundle","wd_bundle","graph_blob"))
    print(f"""
{'─'*52}
  Build Summary
{'─'*52}
  Hot functions       : {len(R['hot_report'].selected_functions)}
  SR-VM functions     : {len(R['bytecodes'])}
  GT-VM DAGs          : {len(R['dags'])}
  Native blocks       : {sum(len(v) for v in R['enc_native'].values())}
  Graph nodes / edges : {len(g.nodes)} / {n_edges}
  Fragments real/junk : {g.n_real} / {g.n_junk}
  Total payload       : {tot:,} bytes
  Build time          : {elapsed:.2f}s
{'─'*52}""")


def main():
    ap = argparse.ArgumentParser(description="ObfTool Stage 0→6")
    ap.add_argument("input"); ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="./build"); ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    run_pipeline(open(a.input).read(), a.input, a.seed, a.out, not a.quiet)

if __name__ == "__main__":
    main()
