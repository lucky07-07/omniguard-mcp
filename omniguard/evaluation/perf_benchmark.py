"""Experiment 2: latency breakdown and storage overhead (R1 vs R2 vs R3).

M MCP `tools/call` requests (default 500, Merkle batch B = 16) are pushed through
the full gateway under each regime with an in-process downstream server. R3
anchors to the local EVM node running in a separate process over HTTP JSON-RPC,
synchronously in the request path, so anchoring cost appears in the tail
latencies (p95/p99) rather than being hidden in a background thread.

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


def run_regime(regime: Regime, work: Path, specs: list[dict[str, Any]], batch_size: int, rpc_url: str | None,
               async_anchor: bool = False) -> dict[str, Any]:
    from omniguard.agents.gateway_agent import build_stack

    label = regime.value + ("-async" if async_anchor else "")
    db = work / f"perf_{label}.db"
    st = build_stack(regime, db, rpc_url=rpc_url, batch_size=batch_size, async_anchor=async_anchor)
    gw = st.gateway
    e2e, security, integrity, audit_total, hash_ms, downstream = [], [], [], [], [], []
    merkle_batches, anchor_batches = [], []
    decisions: dict[str, int] = {}
    for spec in specs:
        t0 = time.perf_counter()
        resp = gw.handle(spec["request"], token=spec["token"], session_id=spec["session_id"])
        e2e.append((time.perf_counter() - t0) * 1000)
        tm = gw.last_timings
        security.append(sum(tm.get(k, 0.0) for k in ("abac_ms", "ingress_ms", "egress_ms")))
        integrity.append(tm.get("integrity_ms", 0.0))
        audit_total.append(tm.get("audit_ms", 0.0))
        hash_ms.append(tm.get("audit_hash_ms", 0.0))
        downstream.append(tm.get("downstream_ms", 0.0))
        if tm.get("audit_merkle_ms", 0.0) > 0:
            merkle_batches.append(tm["audit_merkle_ms"])
        d = (resp.get("result", {}).get("_meta", {}).get("omniguard", {}) or resp.get("error", {}).get("data", {})).get("decision", "?")
        decisions[d] = decisions.get(d, 0) + 1
    st.audit.flush()
    anchor_batches = list(st.audit.anchor_ms)  # per-batch tx time (request path if sync, background if async)
    anchor_in_path = 0.0 if async_anchor else sum(anchor_batches)
    n_events = st.store.count()
    storage = st.store.storage_bytes()
    gas, calldata = list(st.audit.gas_used), list(st.audit.calldata_bytes)
    n_batches = len(st.store.batches())
    st.store.close()
    m = len(specs)
    return {
        "regime": label,
        "anchoring": ("async background worker" if async_anchor else "synchronous in request path") if regime == Regime.R3 else "none",
        "requests": m,
        "decisions": decisions,
        "e2e_latency_ms": summarize(e2e),
        "stage_ms_mean_per_request": {
            "tool_integrity": round(statistics.fmean(integrity), 4),
            "security_engine": round(statistics.fmean(security), 4),
            "downstream_tool": round(statistics.fmean(downstream), 4),
            "audit_total": round(statistics.fmean(audit_total), 4),
            "hash_chain": round(statistics.fmean(hash_ms), 5),
            "merkle_build_amortized": round(sum(merkle_batches) / m, 4),
            "anchor_tx_amortized": round(anchor_in_path / m, 4),
        },
        "per_batch_ms": {
            "merkle_build_mean": round(statistics.fmean(merkle_batches), 4) if merkle_batches else 0.0,
            "anchor_tx_mean": round(statistics.fmean(anchor_batches), 4) if anchor_batches else 0.0,
            "anchor_tx_p95": round(pct(anchor_batches, 95), 4) if anchor_batches else 0.0,
        },
        "security_engine_ms": summarize(security),
        "audit_ms": summarize(audit_total),
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


def run(n_requests: int = 500, batch_size: int = 16, seed: int = 11, warmup: int = 30,
        out_dir: Path = RESULTS_DIR) -> dict[str, Any]:
    compile_contract()
    work = out_dir / "work" / "perf"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    specs = generate_workload(n_requests, seed=seed)
    results: dict[str, Any] = {"config": {"requests": n_requests, "batch_size": batch_size, "seed": seed,
                                          "warmup_requests": warmup, "chain": "eth-tester/py-evm node over HTTP JSON-RPC",
                                          "sqlite": "WAL, synchronous=NORMAL, commit per event"},
                               "regimes": {}}
    with ChainNodeProcess() as node:
        # warm-up (imports, regex compilation, first EVM transactions) - results discarded
        for reg in (Regime.R1, Regime.R3):
            wdir = work / "warmup"
            wdir.mkdir(exist_ok=True)
            run_regime(reg, wdir, generate_workload(warmup, seed=seed + 1), batch_size, node.url)
        for reg, asy in ((Regime.R1, False), (Regime.R2, False), (Regime.R3, False), (Regime.R3, True)):
            r = run_regime(reg, work, specs, batch_size, node.url if reg == Regime.R3 else None, asy)
            results["regimes"][r["regime"]] = r
            print(f"[perf] {r['regime']}: mean {r['e2e_latency_ms']['mean']:.3f} ms, p95 {r['e2e_latency_ms']['p95']:.3f} ms, "
                  f"p99 {r['e2e_latency_ms']['p99']:.3f} ms, {r['storage']['bytes_per_event']} B/event")
    base = results["regimes"]["R1"]["e2e_latency_ms"]
    for reg, r in results["regimes"].items():
        r["overhead_vs_R1"] = {k: {"abs_ms": round(r["e2e_latency_ms"][k] - base[k], 4),
                                   "pct": round(100.0 * (r["e2e_latency_ms"][k] - base[k]) / base[k], 2) if base[k] else 0.0}
                               for k in ("mean", "p50", "p95", "p99")}
    save_json(out_dir / "performance_storage_r1_r2_r3.json", results)
    write_md(results, out_dir)
    return results


def write_md(results: dict[str, Any], out_dir: Path) -> None:
    R = results["regimes"]
    regs = list(R)
    lat = tabulate([[g, *(f"{R[g]['e2e_latency_ms'][k]:.3f}" for k in ("mean", "p50", "p95", "p99")),
                     f"{R[g]['overhead_vs_R1']['mean']['pct']:+.1f}%", f"{R[g]['overhead_vs_R1']['p99']['pct']:+.1f}%"]
                    for g in regs],
                   headers=["Regime", "Mean (ms)", "p50 (ms)", "p95 (ms)", "p99 (ms)", "Mean overhead vs R1",
                            "p99 overhead vs R1"], tablefmt="github")
    stage_keys = list(R["R1"]["stage_ms_mean_per_request"])
    stages = tabulate([[k, *(f"{R[g]['stage_ms_mean_per_request'][k]:.4f}" for g in regs)] for k in stage_keys],
                      headers=["Stage (mean ms / request)", *regs], tablefmt="github")
    batch = tabulate([[g, R[g]["storage"]["merkle_batches"], f"{R[g]['per_batch_ms']['merkle_build_mean']:.3f}",
                       f"{R[g]['per_batch_ms']['anchor_tx_mean']:.3f}", f"{R[g]['per_batch_ms']['anchor_tx_p95']:.3f}"]
                      for g in regs],
                     headers=["Regime", "Batches", "Merkle build / batch (ms)", "Anchor tx / batch (ms)",
                              "Anchor tx p95 (ms)"], tablefmt="github")
    sto = tabulate([[g, R[g]["storage"]["audit_events"], R[g]["storage"]["db_bytes"], R[g]["storage"]["bytes_per_event"],
                     R[g]["storage"]["merkle_proof_bytes"], R[g]["storage"]["onchain_tx"],
                     R[g]["storage"]["onchain_gas_total"], R[g]["storage"]["onchain_gas_per_event"],
                     R[g]["storage"]["onchain_calldata_bytes_total"]] for g in regs],
                   headers=["Regime", "Audit events", "SQLite bytes", "Bytes / event", "Merkle proof bytes",
                            "Anchor txs", "Gas total", "Gas / event", "Calldata bytes"], tablefmt="github")
    c = results["config"]
    md = f"""# Experiment 2 - Latency and storage overhead (R1 vs R2 vs R3)

M = {c['requests']} MCP `tools/call` requests per regime (seed {c['seed']}), Merkle batch size B = {c['batch_size']},
{c['warmup_requests']} warm-up requests discarded. Chain: {c['chain']}. SQLite: {c['sqlite']}.
Latency is wall-clock time through `GatewayAgent.handle` (integrity, ABAC, ingress, downstream call,
egress, audit). R3 anchors synchronously in the request path, so a batch-sealing request carries the
Merkle build and the on-chain transaction.

## End-to-end request latency

{lat}

## Pipeline stage breakdown

{stages}

"Security engine" = ABAC + ingress (canonicalization, structural analyzers, signatures, taint, DLP) + egress
inspection. Merkle and anchor rows are amortized over all requests.

## Per-batch cost (R3)

{batch}

## Storage overhead

{sto}
"""
    (out_dir / "performance_storage_r1_r2_r3.md").write_text(md, encoding="utf-8")


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
