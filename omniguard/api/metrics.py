"""Compact benchmark summary served by GET /api/metrics and written to frontend/metrics.json.

Pure-Python (no FastAPI) so scripts/run_all_experiments.py can build the dashboard's static fallback snapshot.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from omniguard.config import RESULTS_DIR, ROOT, load_json

BENCH_DIR = ROOT / "benchmarks"

METRIC_KEYS = ("n", "precision", "recall_tpr", "f1", "fpr", "tp", "fp", "tn", "fn", "routed_to_ml", "contaminated_rows")


def build_metrics(results_dir: Path = RESULTS_DIR) -> dict[str, Any]:
    def load(name: str) -> Any:
        p = results_dir / name
        return load_json(p) if p.exists() else None

    ext = load("external_dataset_eval.json") or {}
    external: dict[str, Any] = {}
    for sname, st in ext.get("streams", {}).items():
        if st.get("status") != "ok" or "views" not in st:
            continue
        external[sname] = {
            view: ({k: {m: v.get(m) for m in METRIC_KEYS} for k, v in st["views"][view].items()}
                   if st["views"].get(view) else None)
            for view in ("clean", "full")
        }
    cal = load("ml_calibration.json") or {}
    tam = load("tamper_detection_r1_r2_r3.json") or {}
    perf = load("performance_storage_r1_r2_r3.json") or {}
    abl_path = BENCH_DIR / "results.json"
    abl = load_json(abl_path) if abl_path.exists() else None
    return {
        "ablation": ({k: abl[k] for k in ("summary", "modes", "categories", "latency_ms", "sources", "run") if k in abl}
                     if abl else None),
        "engines": ext.get("engines"),
        "protocol": ext.get("protocol"),
        "external": external,
        "calibration": {k: {"chosen": v["chosen"], "rows": v["rows"], "validation_set": v["validation_set"],
                            "rule": v.get("rule"), "f1_surface": v["f1_surface"],
                            "deterministic_only": v.get("deterministic_only_on_validation")}
                        for k, v in cal.get("models", {}).items()},
        "tamper": [{k: r[k] for k in ("scenario", "description", "regime", "detection_rate_pct", "mechanism")}
                   for r in tam.get("rows", [])],
        "latency": {kind: {g: {"mean": r["e2e_latency_ms"]["mean"], "p95": r["e2e_latency_ms"]["p95"],
                               "p99": r["e2e_latency_ms"]["p99"], "routed": r["routed_to_ml"],
                               "requests": r["requests"], "provider": r.get("ml_provider")}
                           for g, r in block["regimes"].items()}
                    for kind, block in perf.get("workloads", {}).items()},
    }
