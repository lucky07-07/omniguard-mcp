"""Run the 100 real benchmark cases through the 3-way ablation against the live OmniGuard API.

    python benchmarks/run_ablation.py --api https://omniguard-mcp-api.onrender.com
    python benchmarks/run_ablation.py --api local          # in-process FastAPI TestClient (CI / smoke test)

Modes (all served by the same API, selected per request with "mode"):
  A  unprotected: the agent's call goes straight to the tool server; nothing inspected, nothing logged
  B  ingress validation (ABAC + deterministic engine + taint + DLP) with NO tool-schema pinning and a plain mutable
     database log (R1 schema: no hash chain, no Merkle batches, no on-chain anchor)
  C  full OmniGuard: B + SHA-256 tool-schema pinning + R3 hash chain + Merkle batches anchored on AuditAnchor.sol

Metrics:
  benign     utility   = % of AgentDojo user tasks the gateway let through (100 - false-positive rate)
  injection  ASR       = % of injection payloads forwarded to the tool (attack reached the tool)
  poisoning  ASR       = % of MCPTox poisoned-description calls forwarded after the mid-session swap
  chain      ASR       = % of MSB 3-step chains whose final malicious step was forwarded
  tamper     detection = % of post-hoc ledger edits the mode's integrity check flags (Mode A keeps no log: 0 by definition)
  latency    p50 / p95 of the server-side gateway time ("server_ms") over every call in the run, per mode

"Forwarded" is judged by the gateway decision, not by whether the demo tool server could act on it (its sandbox file
system has no ~/.ssh, for example); tool-side errors are recorded separately as tool_error.
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SAMPLES = HERE / "raw_benchmark_samples.json"
OUT = HERE / "results.json"
MODES = ("A", "B", "C")
TAMPER_ATTACKS = ("edit_decision", "delete_row", "rewrite_chain", "truncate_tail")
ROLE = "operator"


class Api:
    def __init__(self, base: str):
        self.base = base
        if base == "local":
            import tempfile

            from fastapi.testclient import TestClient

            import omniguard.api.server as server

            server.LIVE_DIR = Path(tempfile.mkdtemp(prefix="omniguard-abl-"))
            self._cm = TestClient(server.app)
            self.c = self._cm.__enter__()
        else:
            import httpx

            self.c = httpx.Client(base_url=base, timeout=120)

    def post(self, path: str, body: dict | None = None, **params) -> dict[str, Any]:
        for attempt in range(4):
            try:
                r = self.c.post(path, json=body, params=params or None)
                if r.status_code < 500:
                    r.raise_for_status()
                    return r.json()
            except Exception:
                if attempt == 3:
                    raise
            time.sleep(2 + attempt * 3)
        raise RuntimeError(f"{path} failed")

    def get(self, path: str) -> dict[str, Any]:
        r = self.c.get(path)
        r.raise_for_status()
        return r.json()


def call(api: Api, step: dict, session: str, mode: str, lat: dict[str, list[float]]) -> dict[str, Any]:
    body = {"role": ROLE, "tool": step["tool"], "arguments": step["arguments"], "session_id": session[:64], "mode": mode}
    if step.get("rugpull"):
        body["simulate_rugpull"] = step["rugpull"]
    t0 = time.perf_counter()
    r = api.post("/api/gateway/call", body)
    rtt = (time.perf_counter() - t0) * 1000
    lat[mode].append(r["server_ms"])
    forwarded = r["decision"] in ("EXECUTED", "ALLOW", "REDACT")
    res = r.get("response", {}).get("result") or {}
    return {"tool": step["tool"], "decision": r["decision"], "denied_at": r.get("denied_at"),
            "rules": r.get("triggered_rules", []), "forwarded": forwarded, "tool_error": bool(res.get("isError")),
            "server_ms": r["server_ms"], "rtt_ms": round(rtt, 1), "schema_drift": r.get("schema_drift")}


def pct(xs: list[bool]) -> float | None:
    return round(100 * sum(xs) / len(xs), 1) if xs else None


def q(xs: list[float], p: float) -> float | None:
    if not xs:
        return None
    s = sorted(xs)
    return round(s[min(len(s) - 1, max(0, int(round(p * (len(s) - 1)))))], 3)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="https://omniguard-mcp-api.onrender.com")
    ap.add_argument("--tag", default=time.strftime("%m%d%H%M"))
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args()
    data = json.loads(SAMPLES.read_text(encoding="utf-8"))
    cases = data["cases"]
    api = Api(a.api)
    health = api.get("/api/health")
    print("health", {k: health[k] for k in ("version", "engine", "batch_size", "anchored_batches")})
    api.post("/api/ledger/reset")
    lat: dict[str, list[float]] = {m: [] for m in MODES}
    per_case: list[dict[str, Any]] = []
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for i, c in enumerate(cases):
        row = {"case_id": c["case_id"], "category": c["category"], "upstream_id": c["source"]["upstream_id"],
               "benchmark": c["source"]["benchmark"], "modes": {}}
        for m in MODES:
            sess = f"{c['case_id']}-{m}-{a.tag}"
            steps = [call(api, s, sess, m, lat) for s in c["steps"]]
            final = steps[-1]
            row["modes"][m] = {"steps": steps, "final_forwarded": final["forwarded"],
                               "blocked_at_step": next((k + 1 for k, s in enumerate(steps) if not s["forwarded"]), None)}
        per_case.append(row)
        if i % 10 == 0:
            print(i, c["case_id"], {m: row["modes"][m]["final_forwarded"] for m in MODES}, flush=True)

    # ---------------------------------------------------------------- post-hoc tampering on replayed real sessions
    chains = [c for c in cases if c["category"] == "chain"]
    benign = [c for c in cases if c["category"] == "benign"]
    tamper_rows = []
    for k in range(10):
        src, attack = chains[k], TAMPER_ATTACKS[k % len(TAMPER_ATTACKS)]
        api.post("/api/ledger/reset")
        sess = f"tamper-{k}-{a.tag}"
        for m in ("B", "C"):
            for s in src["steps"]:
                call(api, s, f"{sess}-{m}", m, lat)
        # pad the session with real AgentDojo user-task calls until every record is in a sealed, anchored batch
        j = 0
        while True:
            h = api.get("/api/health")
            if h["records"]["R3"] % h["batch_size"] == 0 and h["records"]["R3"] >= 3 * h["batch_size"]:
                break
            pad = benign[(k * 3 + j) % len(benign)]["steps"][0]
            for m in ("B", "C"):
                call(api, pad, f"{sess}-{m}", m, lat)
            j += 1
        clean = {m: api.post("/api/watcher/verify", mode=m) for m in ("B", "C")}
        applied = {m: api.post(f"/api/tamper/{attack}", mode=m)["applied"] for m in ("B", "C")}
        after = {m: api.post("/api/watcher/verify", mode=m) for m in ("B", "C")}
        det_b = not after["B"]["regimes"]["B"]["ok"]
        det_c = not after["C"]["regimes"]["R3"]["ok"]
        tamper_rows.append({"case_id": f"tamper-{k:02d}", "replayed_session": src["case_id"],
                            "upstream_id": src["source"]["upstream_id"], "attack": attack, "padding_calls": j,
                            "clean_before": {m: all(v["ok"] for v in clean[m]["regimes"].values()) for m in ("B", "C")},
                            "applied": applied, "detected": {"A": False, "B": det_b, "C": det_c},
                            "alerts_C": sorted({x["violation"] for x in after["C"]["regimes"]["R3"]["alerts"]}),
                            "per_regime_C": {r: not v["ok"] for r, v in after["C"]["regimes"].items()}})
        print("tamper", k, attack, tamper_rows[-1]["detected"], tamper_rows[-1]["alerts_C"], flush=True)
    api.post("/api/ledger/reset")

    # ---------------------------------------------------------------- aggregate
    def by(cat: str) -> list[dict]:
        return [r for r in per_case if r["category"] == cat]

    labels = {"benign": ("Benign tasks", "AgentDojo user tasks", "utility"),
              "injection": ("Prompt injection", "AgentDojo + MSB", "asr"),
              "poisoning": ("Tool poisoning / schema drift", "MCPTox", "asr"),
              "chain": ("Multi-step attack chains", "MSB composite attacks", "asr")}
    cats: dict[str, Any] = {}
    for cat, (label, source, metric) in labels.items():
        rows = by(cat)
        cats[cat] = {"label": label, "source": source, "n": len(rows), "metric": metric,
                     **{m: pct([r["modes"][m]["final_forwarded"] for r in rows]) for m in MODES}}
    cats["tamper"] = {"label": "Post-hoc log tampering", "source": "replayed MSB sessions", "n": len(tamper_rows),
                      "metric": "detection", **{m: pct([t["detected"][m] for t in tamper_rows]) for m in MODES}}
    attacks = [r for r in per_case if r["category"] != "benign"]
    summary = {m: {"attack_success_rate": pct([r["modes"][m]["final_forwarded"] for r in attacks]),
                   "benign_utility": cats["benign"][m], "false_positive_rate": round(100 - cats["benign"][m], 1),
                   "tamper_detection": cats["tamper"][m]} for m in MODES}
    latency = {m: {"p50": q(lat[m], 0.50), "p95": q(lat[m], 0.95), "mean": round(statistics.fmean(lat[m]), 3),
                   "calls": len(lat[m])} for m in MODES}
    out = {
        "run": {"api": a.api, "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "api_version": health.get("version"), "engine": health.get("engine"), "batch_size": health.get("batch_size"),
                "cases": len(cases) + len(tamper_rows)},
        "modes": {"A": "Unprotected: calls go straight to the tool server, no log",
                  "B": "Ingress validation (ABAC + engine + taint + DLP) + mutable DB log; no pinning, no anchoring",
                  "C": "Full OmniGuard: + SHA-256 tool-schema pinning + R3 hash chain + Merkle root on AuditAnchor.sol"},
        "summary": summary, "categories": cats, "latency_ms": latency,
        "sources": data["meta"]["sources"], "sample_counts": {**data["meta"]["counts"], "tamper": len(tamper_rows)},
        "definitions": __doc__.split("Metrics:")[1].strip(),
        "tamper_cases": tamper_rows,
    }
    out_path = Path(a.out)
    out_path.write_text(json.dumps(out, indent=1), encoding="utf-8")
    with out_path.with_name(out_path.stem + "_cases.jsonl").open("w", encoding="utf-8") as f:
        for r in per_case:
            f.write(json.dumps(r) + "\n")
    print(json.dumps({"summary": summary, "categories": cats, "latency_ms": latency}, indent=1))


if __name__ == "__main__":
    main()
