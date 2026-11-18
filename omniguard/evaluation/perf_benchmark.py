"""Experiment 2: latency breakdown and storage overhead (R1 vs R2 vs R3), split by inspection path.

Two workloads of M requests each are pushed through the full gateway under every regime:

* structured   - structured arguments and structured outputs (SQL, shell, listings, short messages):
                 the deterministic fast path, never routed to the ML stage
* unstructured - free-text arguments (> 40 chars) and free-text tool outputs: the hybrid path, where the
                 integrity-pinned ONNX classifier runs on the GPU (CUDA EP) after the deterministic checks

R3 anchors to the local EVM node (separate process, HTTP JSON-RPC) synchronously in the request path,
R3-async from a background worker. A warm-up pass (both workloads, GPU included) runs before timing.

    python -m omniguard.evaluation.perf_benchmark --requests 500 --batch-size 16
"""

from __future__ import annotations

import argparse
import shutil
import statistics
import time
from pathlib import Path
from typing import Any

from tabulate import tabulate

from omniguard.config import RESULTS_DIR, save_json
from omniguard.crypto.blockchain import compile_contract
from omniguard.crypto.chain_node import ChainNodeProcess
from omniguard.evaluation.workload import generate_workload
from omniguard.models import Regime

WORKLOADS = ("structured", "unstructured")
VARIANTS = ((Regime.R1, False), (Regime.R2, False), (Regime.R3, False), (Regime.R3, True))


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "mean": round(statistics.fmean(values), 4) if values else 0.0,
        "p50": round(pct(values, 50), 4),
        "p95": round(pct(values, 95), 4),
        "p99": round(pct(values, 99), 4),
        "max": round(max(values), 4) if values else 0.0,
    }


def _mean(xs: list[float]) -> float:
    return round(statistics.fmean(xs), 4) if xs else 0.0


def run_regime(regime: Regime, work: Path, specs: list[dict[str, Any]], batch_size: int, rpc_url: str | None,
               async_anchor: bool = False, tag: str = "") -> dict[str, Any]:
    from omniguard.agents.gateway_agent import build_stack

    label = regime.value + ("-async" if async_anchor else "")
    st = build_stack(regime, work / f"perf_{tag}_{label}.db", rpc_url=rpc_url, batch_size=batch_size,
                     async_anchor=async_anchor, ml="auto")
    gw = st.gateway
    cols: dict[str, list[float]] = {k: [] for k in ("e2e", "det", "ml_tok", "ml_inf", "integrity", "downstream",
                                                    "audit", "hash")}
    merkle_batches: list[float] = []
    e2e_by_path: dict[str, list[float]] = {"deterministic": [], "hybrid_ml": []}
    ml_routed_infer: list[float] = []
    decisions: dict[str, int] = {}
    for spec in specs:
        t0 = time.perf_counter()
        resp = gw.handle(spec["request"], token=spec["token"], session_id=spec["session_id"])
        e2e = (time.perf_counter() - t0) * 1000
        tm = gw.last_timings
        ml_tok, ml_inf = tm.get("ml_tokenize_ms", 0.0), tm.get("ml_infer_ms", 0.0)
        cols["e2e"].append(e2e)
        cols["det"].append(sum(tm.get(k, 0.0) for k in ("abac_ms", "ingress_ms", "egress_ms")) - ml_tok - ml_inf)
        cols["ml_tok"].append(ml_tok)
        cols["ml_inf"].append(ml_inf)
        cols["integrity"].append(tm.get("integrity_ms", 0.0))
        cols["downstream"].append(tm.get("downstream_ms", 0.0))
        cols["audit"].append(tm.get("audit_ms", 0.0))
        cols["hash"].append(tm.get("audit_hash_ms", 0.0))
        path = tm.get("inspection_path", "deterministic")
        e2e_by_path[path].append(e2e)
        if path == "hybrid_ml":
            ml_routed_infer.append(ml_inf)
        if tm.get("audit_merkle_ms", 0.0) > 0:
            merkle_batches.append(tm["audit_merkle_ms"])
        d = (resp.get("result", {}).get("_meta", {}).get("omniguard", {}) or resp.get("error", {}).get("data", {})).get("decision", "?")
        decisions[d] = decisions.get(d, 0) + 1
    st.audit.flush()
    anchor_batches = list(st.audit.anchor_ms)
    anchor_in_path = 0.0 if async_anchor else sum(anchor_batches)
    n_events = st.store.count()
    storage = st.store.storage_bytes()
    gas, calldata = list(st.audit.gas_used), list(st.audit.calldata_bytes)
    n_batches = len(st.store.batches())
    clf = gw.engine.ml
    st.store.close()
    m = len(specs)
    return {
        "regime": label,
        "anchoring": ("async background worker" if async_anchor else "synchronous in request path") if regime == Regime.R3 else "none",
        "requests": m,
        "routed_to_ml": len(e2e_by_path["hybrid_ml"]),
        "ml_provider": clf.provider if clf is not None else None,
        "decisions": decisions,
        "e2e_latency_ms": summarize(cols["e2e"]),
        "e2e_latency_ms_by_path": {k: summarize(v) for k, v in e2e_by_path.items() if v},
        "ml_infer_ms_when_routed": summarize(ml_routed_infer),
        "stage_ms_mean_per_request": {
            "tool_integrity": _mean(cols["integrity"]),
            "deterministic_engine": _mean(cols["det"]),
            "ml_tokenize": _mean(cols["ml_tok"]),
            "ml_onnx_inference": _mean(cols["ml_inf"]),
            "downstream_tool": _mean(cols["downstream"]),
            "audit_total": _mean(cols["audit"]),
            "hash_chain": round(statistics.fmean(cols["hash"]), 5),
            "merkle_build_amortized": round(sum(merkle_batches) / m, 4),
            "anchor_tx_amortized": round(anchor_in_path / m, 4),
        },
        "per_batch_ms": {
            "merkle_build_mean": _mean(merkle_batches),
            "anchor_tx_mean": _mean(anchor_batches),
            "anchor_tx_p95": round(pct(anchor_batches, 95), 4) if anchor_batches else 0.0,
        },
        "deterministic_engine_ms": summarize(cols["det"]),
        "storage": {
            "audit_events": n_events,
            "db_bytes": storage["db_bytes"],
            "bytes_per_event": round(storage["db_bytes"] / max(n_events, 1), 2),
            "merkle_proof_bytes": storage.get("merkle_proof_bytes", 0),
            "merkle_batches": n_batches,
            "onchain_tx": len(gas),
            "onchain_gas_total": int(sum(gas)),
            "onchain_gas_per_batch": round(statistics.fmean(gas), 1) if gas else 0,
            "onchain_gas_per_event": round(sum(gas) / max(n_events, 1), 1),
            "onchain_calldata_bytes_total": int(sum(calldata)),
            "onchain_calldata_bytes_per_event": round(sum(calldata) / max(n_events, 1), 2),
        },
    }


def run(n_requests: int = 500, batch_size: int = 16, seed: int = 11, warmup: int = 40,
        out_dir: Path = RESULTS_DIR) -> dict[str, Any]:
    compile_contract()
    work = out_dir / "work" / "perf"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    results: dict[str, Any] = {
        "config": {"requests_per_workload": n_requests, "batch_size": batch_size, "seed": seed,
                   "warmup_requests": warmup, "chain": "eth-tester/py-evm node over HTTP JSON-RPC",
                   "sqlite": "WAL, synchronous=NORMAL, commit per event"},
        "workloads": {},
    }
    with ChainNodeProcess() as node:
        wdir = work / "warmup"
        wdir.mkdir()
        for kind in WORKLOADS:  # warm-up: imports, regexes, CUDA context/kernels, first EVM txs - discarded
            for reg, asy in ((Regime.R1, False), (Regime.R3, False)):
                run_regime(reg, wdir, generate_workload(warmup, seed=seed + 1, kind=kind), batch_size, node.url,
                           asy, tag=f"warm_{kind}")
        for kind in WORKLOADS:
            specs = generate_workload(n_requests, seed=seed, kind=kind)
            res_k: dict[str, Any] = {}
            for reg, asy in VARIANTS:
                r = run_regime(reg, work, specs, batch_size, node.url if reg == Regime.R3 else None, asy, tag=kind)
                res_k[r["regime"]] = r
                print(f"[perf] {kind:12s} {r['regime']:8s} routed={r['routed_to_ml']:3d} "
                      f"mean {r['e2e_latency_ms']['mean']:.3f} ms  p95 {r['e2e_latency_ms']['p95']:.3f}  "
                      f"p99 {r['e2e_latency_ms']['p99']:.3f}  ({r['ml_provider']})")
            base = res_k["R1"]["e2e_latency_ms"]
            for r in res_k.values():
                r["overhead_vs_R1"] = {k: {"abs_ms": round(r["e2e_latency_ms"][k] - base[k], 4),
                                           "pct": round(100.0 * (r["e2e_latency_ms"][k] - base[k]) / base[k], 2) if base[k] else 0.0}
                                       for k in ("mean", "p50", "p95", "p99")}
            results["workloads"][kind] = {"regimes": res_k}
    save_json(out_dir / "performance_storage_r1_r2_r3.json", results)
    write_md(results, out_dir)
    return results


def write_md(results: dict[str, Any], out_dir: Path) -> None:
    c = results["config"]
    parts = [f"""# Experiment 2 - Latency and storage overhead (R1 vs R2 vs R3), fast path vs hybrid path

M = {c['requests_per_workload']} MCP `tools/call` requests per workload and regime (seed {c['seed']}), Merkle batch
size B = {c['batch_size']}; {c['warmup_requests']} warm-up requests per workload (GPU included) discarded.
Chain: {c['chain']}. SQLite: {c['sqlite']}. Latency is wall-clock time through `GatewayAgent.handle`.

* **structured** - structured arguments and outputs only: deterministic fast path, never routed to the model.
* **unstructured** - free-text arguments (> 40 chars) or free-text tool outputs: hybrid path, ONNX classifier
  on the GPU after the deterministic checks pass (requests the deterministic engine already denies are not routed).
"""]
    for kind, block in results["workloads"].items():
        R = block["regimes"]
        regs = list(R)
        prov = next((r["ml_provider"] for r in R.values() if r["ml_provider"]), "n/a")
        lat = tabulate([[g, R[g]["routed_to_ml"], *(f"{R[g]['e2e_latency_ms'][k]:.3f}" for k in ("mean", "p50", "p95", "p99")),
                         f"{R[g]['overhead_vs_R1']['mean']['pct']:+.1f}%", f"{R[g]['overhead_vs_R1']['p99']['pct']:+.1f}%"]
                        for g in regs],
                       headers=["Regime", "Routed to ML", "Mean (ms)", "p50", "p95", "p99", "Mean vs R1", "p99 vs R1"],
                       tablefmt="github")
        keys = list(R["R1"]["stage_ms_mean_per_request"])
        stages = tabulate([[k, *(f"{R[g]['stage_ms_mean_per_request'][k]:.4f}" for g in regs)] for k in keys],
                          headers=["Stage (mean ms / request)", *regs], tablefmt="github")
        ml = R["R1"]["ml_infer_ms_when_routed"]
        batch = tabulate([[g, R[g]["storage"]["merkle_batches"], f"{R[g]['per_batch_ms']['merkle_build_mean']:.3f}",
                           f"{R[g]['per_batch_ms']['anchor_tx_mean']:.3f}", f"{R[g]['per_batch_ms']['anchor_tx_p95']:.3f}"]
                          for g in regs if g.startswith("R3")],
                         headers=["Regime", "Batches", "Merkle build / batch (ms)", "Anchor tx / batch (ms)",
                                  "Anchor tx p95 (ms)"], tablefmt="github")
        sto = tabulate([[g, R[g]["storage"]["audit_events"], R[g]["storage"]["db_bytes"], R[g]["storage"]["bytes_per_event"],
                         R[g]["storage"]["merkle_proof_bytes"], R[g]["storage"]["onchain_tx"],
                         R[g]["storage"]["onchain_gas_total"], R[g]["storage"]["onchain_gas_per_event"],
                         R[g]["storage"]["onchain_calldata_bytes_total"]] for g in regs],
                       headers=["Regime", "Audit events", "SQLite bytes", "Bytes / event", "Merkle proof bytes",
                                "Anchor txs", "Gas total", "Gas / event", "Calldata bytes"], tablefmt="github")
        ml_line = (f"ONNX inference when routed (execution provider **{prov}**): mean {ml['mean']:.2f} ms, "
                   f"p50 {ml['p50']:.2f}, p95 {ml['p95']:.2f}, p99 {ml['p99']:.2f} ms (R1 run).\n\n") if R["R1"]["routed_to_ml"] else ""
        parts.append(f"""
## Workload: {kind}

### End-to-end request latency

{lat}

{ml_line}### Pipeline stage breakdown

{stages}

"deterministic_engine" = ABAC + ingress + egress inspection excluding ML tokenization/inference; Merkle and anchor
rows are amortized over all requests.

### Per-batch cost (R3)

{batch}

### Storage overhead

{sto}
""")
    (out_dir / "performance_storage_r1_r2_r3.md").write_text("".join(parts), encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--requests", type=int, default=500)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--out", default=str(RESULTS_DIR))
    a = ap.parse_args(argv)
    run(a.requests, a.batch_size, a.seed, out_dir=Path(a.out))


if __name__ == "__main__":
    main()
