"""Single-command runner for every OmniGuard-MCP experiment.

    python scripts/run_all_experiments.py [--max-samples 500] [--trials 5] [--requests 500]

Produces in results/:
    external_dataset_eval.json / .md
    tamper_detection_r1_r2_r3.json / .md
    performance_storage_r1_r2_r3.json / .md
    *.png summary figures
    SUMMARY.md

The hybrid ML thresholds are NOT recalibrated here: they were calibrated once on the validation set
(`python -m omniguard.evaluation.calibrate_ml --write` -> results/ml_calibration.json) and frozen.
Also refreshes frontend/metrics.json (the dashboard's static fallback).
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from omniguard.config import RESULTS_DIR  # noqa: E402
from omniguard.evaluation import external_dataset_eval, perf_benchmark, tamper_experiments  # noqa: E402

# Reference categorical palette (fixed order, never cycled) + neutral ink.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
REGIME_COLOR = {"R1": SERIES[0], "R2": SERIES[1], "R3": SERIES[2], "R3-async": SERIES[3]}


def style() -> None:
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
        "text.color": INK, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8,
        "axes.spines.top": False, "axes.spines.right": False, "axes.axisbelow": True,
        "font.size": 10, "axes.titlesize": 12, "axes.titleweight": "bold", "legend.frameon": False,
    })


def bar(ax, x, h, w, color, label=None):
    return ax.bar(x, h, w, color=color, label=label, edgecolor=SURFACE, linewidth=1.5)


def plot_latency(perf: dict, out: Path) -> None:
    stats = ["mean", "p50", "p95", "p99"]
    kinds = list(perf["workloads"])
    fig, axes = plt.subplots(1, len(kinds), figsize=(11, 4.4), sharey=True)
    for ax, kind in zip(np.atleast_1d(axes), kinds):
        R = perf["workloads"][kind]["regimes"]
        regs = list(R)
        w = 0.8 / len(regs)
        x = np.arange(len(stats))
        for i, g in enumerate(regs):
            bar(ax, x + (i - (len(regs) - 1) / 2) * w, [R[g]["e2e_latency_ms"][st] for st in stats], w, REGIME_COLOR[g], g)
        ax.set_yscale("log")
        ax.set_xticks(x, ["Mean", "p50", "p95", "p99"])
        routed = R["R1"]["routed_to_ml"]
        ax.set_title(f"{kind} ({routed}/{R['R1']['requests']} routed to ML)", loc="left", fontsize=11)
    np.atleast_1d(axes)[0].set_ylabel("End-to-end latency per tools/call (ms, log)")
    np.atleast_1d(axes)[0].legend(ncol=2, loc="upper left", fontsize=8.5)
    fig.suptitle(f"Request latency, M={perf['config']['requests_per_workload']} per workload, "
                 f"B={perf['config']['batch_size']}", x=0.01, ha="left", fontweight="bold")
    fig.tight_layout()
    fig.savefig(out / "latency_r1_r2_r3.png", dpi=160)
    plt.close(fig)


def plot_breakdown(perf: dict, out: Path) -> None:
    stages = [("tool_integrity", "Tool integrity"), ("deterministic_engine", "Deterministic engine"),
              ("ml_tokenize", "ML tokenize"), ("ml_onnx_inference", "ONNX inference (GPU)"),
              ("downstream_tool", "Downstream tool"), ("hash_chain", "Hash chain"),
              ("merkle_build_amortized", "Merkle build (amortized)"), ("anchor_tx_amortized", "Anchor tx (amortized)")]
    kinds = list(perf["workloads"])
    limits = {"structured": 1.0, "unstructured": 25.0}
    fig, axes = plt.subplots(len(kinds), 1, figsize=(9, 2.6 * len(kinds) + 1.2))
    for ax, kind in zip(np.atleast_1d(axes), kinds):
        R = perf["workloads"][kind]["regimes"]
        regs = list(R)
        left = np.zeros(len(regs))
        for j, (k, name) in enumerate(stages):
            vals = np.array([R[g]["stage_ms_mean_per_request"][k] for g in regs])
            ax.barh(regs, vals, left=left, color=SERIES[j], label=name, edgecolor=SURFACE, linewidth=1.2, height=0.6)
            left += vals
        rest = np.array([R[g]["e2e_latency_ms"]["mean"] for g in regs]) - left
        ax.barh(regs, np.clip(rest, 0, None), left=left, color="#c9c8c2", label="SQLite write + other",
                edgecolor=SURFACE, linewidth=1.2, height=0.6)
        xmax = limits.get(kind, float(max(R[g]["e2e_latency_ms"]["mean"] for g in regs)) * 1.15)
        for i, g in enumerate(regs):
            total = R[g]["e2e_latency_ms"]["mean"]
            if total > xmax:
                ax.text(xmax * 0.985, i, f"clipped: total {total:.2f} ms ", va="center", ha="right",
                        color="#ffffff", fontsize=8.5, fontweight="bold")
            else:
                ax.text(total, i, f"  {total:.2f} ms", va="center", color=INK2, fontsize=9)
        ax.set_xlim(0, xmax)
        ax.invert_yaxis()
        ax.set_title(f"{kind} workload - mean ms per request (linear, clipped at {xmax:g} ms)", loc="left", fontsize=11)
    np.atleast_1d(axes)[-1].legend(ncol=3, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.18))
    fig.tight_layout()
    fig.savefig(out / "latency_breakdown_r1_r2_r3.png", dpi=160, bbox_inches="tight")
    plt.close(fig)


def plot_storage(perf: dict, out: Path) -> None:
    R = perf["workloads"]["structured"]["regimes"]
    regs = [g for g in R if g != "R3-async"]
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.8))
    vals = [R[g]["storage"]["bytes_per_event"] for g in regs]
    bars = axes[0].bar(regs, vals, color=[REGIME_COLOR[g] for g in regs], edgecolor=SURFACE, linewidth=1.5, width=0.6)
    axes[0].bar_label(bars, fmt="%.0f B", color=INK2, padding=2)
    axes[0].set_title("Local SQLite bytes per audit event", loc="left")
    axes[0].set_ylabel("bytes / event")
    gas = [R[g]["storage"]["onchain_gas_per_event"] for g in regs]
    bars = axes[1].bar(regs, gas, color=[REGIME_COLOR[g] for g in regs], edgecolor=SURFACE, linewidth=1.5, width=0.6)
    axes[1].bar_label(bars, fmt="%.0f", color=INK2, padding=2)
    axes[1].set_title("On-chain gas per audit event", loc="left")
    axes[1].set_ylabel("gas / event (batch size B)")
    fig.tight_layout()
    fig.savefig(out / "storage_r1_r2_r3.png", dpi=160)
    plt.close(fig)


def plot_tamper(tamper: dict, out: Path) -> None:
    from matplotlib.colors import LinearSegmentedColormap

    ids = [s[0] for s in tamper_experiments.SCENARIOS]
    names = [s[1] for s in tamper_experiments.SCENARIOS]
    regs = ["R1", "R2", "R3"]
    M = np.array([[next(r for r in tamper["rows"] if r["scenario"] == sid and r["regime"] == g)["detection_rate_pct"]
                   for g in regs] for sid in ids])
    cmap = LinearSegmentedColormap.from_list("blue", ["#eef4fc", "#2a78d6", "#0d3a73"])
    fig, ax = plt.subplots(figsize=(8.5, 4.4))
    ax.imshow(M, cmap=cmap, vmin=0, vmax=100, aspect="auto")
    ax.grid(False)
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            v = M[i, j]
            ax.text(j, i, f"{'Detected' if v == 100 else ('Missed' if v == 0 else 'Partial')}\n{v:.0f}%",
                    ha="center", va="center", fontsize=8.5, color="#ffffff" if v >= 50 else INK)
    ax.set_xticks(range(3), regs)
    ax.set_yticks(range(len(ids)), [f"{i}  {n}" for i, n in zip(ids, names)], fontsize=8.5)
    ax.set_xticks(np.arange(-.5, 3, 1), minor=True)
    ax.set_yticks(np.arange(-.5, len(ids), 1), minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2)
    ax.tick_params(which="minor", length=0)
    ax.set_title("Tamper detection rate by audit regime", loc="left")
    fig.tight_layout()
    fig.savefig(out / "tamper_detection_r1_r2_r3.png", dpi=160)
    plt.close(fig)


ENGINE_ORDER = ["v1.0", "v1.1", "v1.2", "v1.2-small"]


def _ext_view(st: dict) -> tuple[str, dict]:
    """Headline view per stream: contamination-controlled (official test split) when it exists, else full."""
    if st["views"].get("clean"):
        return "clean", st["views"]["clean"]
    return "full", st["views"]["full"]


def plot_external(ext: dict, out: Path) -> None:
    ok = {k: v for k, v in ext["streams"].items() if v.get("status") == "ok" and "views" in v}
    if not ok:
        return
    engines = [e for e in ENGINE_ORDER if ext["engines"].get(e, {}).get("available")]
    metrics = [("precision", "Precision"), ("recall_tpr", "Recall"), ("f1", "F1")]
    fig, axes = plt.subplots(1, 3, figsize=(14, 5.2), sharey=True)
    names = []
    for k, v in ok.items():
        view, _ = _ext_view(v)
        short = {"prompt_injection_ingress": "Prompt inj.\n(args)", "prompt_injection_egress": "Indirect inj.\n(outputs)",
                 "jailbreak_ingress": "Jailbreak", "sql_injection": "SQL inj.", "command_injection": "Command inj."}
        names.append(short.get(k, k) + ("\ntest split" if view == "clean" else "\nheld-out"))
    x = np.arange(len(ok))
    w = 0.8 / len(engines)
    for ax, (mk, mname) in zip(axes, metrics):
        for i, e in enumerate(engines):
            vals = [_ext_view(v)[1].get(e, {}).get(mk, 0.0) for v in ok.values()]
            b = bar(ax, x + (i - (len(engines) - 1) / 2) * w, vals, w, SERIES[i], ext["engines"][e]["label"])
            if mk == "f1" and e == "v1.2":
                ax.bar_label(b, fmt="%.2f", color=INK2, fontsize=7.5, padding=2)
        ax.set_xticks(x, names, fontsize=8)
        ax.set_ylim(0, 1.1)
        ax.set_title(mname, loc="left", fontsize=11)
    axes[0].set_ylabel("score on held-out data")
    h, l = axes[0].get_legend_handles_labels()
    fig.suptitle("Held-out detection: v1.0 deterministic vs v1.1 / v1.2 hybrid", x=0.01, y=0.985, ha="left", fontweight="bold")
    fig.legend(h, l, ncol=4, loc="upper left", bbox_to_anchor=(0.01, 0.93), fontsize=9, frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.86))
    fig.savefig(out / "external_dataset_eval.png", dpi=160)
    plt.close(fig)


def write_summary(ext: dict, tamper: dict, perf: dict, out: Path, elapsed: float) -> None:
    lines = ["# OmniGuard-MCP - experiment summary", "",
             f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} on {platform.platform()} / Python {platform.python_version()}, "
             f"total runtime {elapsed / 60:.1f} min.", "", "## Engines", "",
             "| Key | Engine | Model | Provider | Thresholds (milli) |", "|---|---|---|---|---|"]
    for k, e in ext["engines"].items():
        thr = e.get("thresholds_milli")
        t = f"{thr['clean']} / {thr['elevated']}" + (" + rule-hit cascade" if thr["elevate_on_rule_hit"] else "") if thr else "-"
        lines.append(f"| {k} | {e['label']} | {e['model'] or '-'} | {e.get('provider') or '-'} | {t} |")
    lines += ["", "## External validation (held-out; prompt-injection rows = official test split only)", "",
              "| Stream | View | n | " + " | ".join(f"{k} F1" for k in ENGINE_ORDER if k in ext['engines']) + " | v1.2 P / R |",
              "|---|---|---|" + "---|" * (len([k for k in ENGINE_ORDER if k in ext['engines']]) + 1)]
    for sname, st in ext["streams"].items():
        if st.get("status") != "ok":
            lines.append(f"| {sname} | - | - | {st.get('status')} |")
            continue
        view, v = _ext_view(st)
        n = next(iter(v.values()))["n"]
        f1s = " | ".join(f"{v[k]['f1']:.3f}{' ⚠' if v[k]['contaminated_rows'] else ''}" if k in v else "-"
                         for k in ENGINE_ORDER if k in ext["engines"])
        p12 = f"{v['v1.2']['precision']:.3f} / {v['v1.2']['recall_tpr']:.3f}" if "v1.2" in v else "-"
        lines.append(f"| {sname} | {view} | {n} | {f1s} | {p12} |")
    lines += ["", "⚠ = rows overlap that model's published training data.", "",
              "## Tamper detection (trials detected)", "", "| Regime | Detected | Rate |", "|---|---|---|"]
    for g in ("R1", "R2", "R3"):
        rr = [r for r in tamper["rows"] if r["regime"] == g]
        d, t = sum(r["detected_trials"] for r in rr), sum(r["trials"] for r in rr)
        lines.append(f"| {g} | {d}/{t} | {100 * d / t:.1f}% |")
    lines += ["", "## Latency (ms) by workload", "",
              "| Workload | Regime | Routed to ML | Mean | p95 | p99 | Det. engine | ONNX infer | Bytes/event |",
              "|---|---|---|---|---|---|---|---|---|"]
    for kind, block in perf["workloads"].items():
        for g, r in block["regimes"].items():
            e, st = r["e2e_latency_ms"], r["stage_ms_mean_per_request"]
            lines.append(f"| {kind} | {g} | {r['routed_to_ml']}/{r['requests']} | {e['mean']:.3f} | {e['p95']:.3f} | "
                         f"{e['p99']:.3f} | {st['deterministic_engine']:.3f} | {st['ml_onnx_inference']:.3f} | "
                         f"{r['storage']['bytes_per_event']} |")
    lines += ["", "Details: `external_dataset_eval.md`, `ml_calibration.json`, `tamper_detection_r1_r2_r3.md`, "
                  "`performance_storage_r1_r2_r3.md`."]
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_frontend_snapshot(out: Path) -> None:
    """Static fallback for the Vercel dashboard when the Render API is asleep."""
    from omniguard.api.metrics import build_metrics

    snap = build_metrics(out)
    (ROOT / "frontend" / "metrics.json").write_text(json.dumps(snap, separators=(",", ":")), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Run every OmniGuard-MCP experiment")
    ap.add_argument("--max-samples", type=int, default=500)
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--requests", type=int, default=500)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--out", default=str(RESULTS_DIR))
    ap.add_argument("--plots-only", action="store_true", help="re-draw figures from existing JSON results")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    style()
    t0 = time.time()
    if a.plots_only:
        ext = json.loads((out / "external_dataset_eval.json").read_text(encoding="utf-8"))
        tamper = json.loads((out / "tamper_detection_r1_r2_r3.json").read_text(encoding="utf-8"))
        perf = json.loads((out / "performance_storage_r1_r2_r3.json").read_text(encoding="utf-8"))
    else:
        print("== [1/3] External dataset validation (Hugging Face streaming)")
        ext = external_dataset_eval.run(max_samples=a.max_samples, out_dir=out)
        print("== [2/3] Tamper detection R1 vs R2 vs R3")
        tamper = tamper_experiments.run(trials=a.trials, batch_size=a.batch_size, out_dir=out)
        print("== [3/3] Latency and storage overhead R1 vs R2 vs R3")
        perf = perf_benchmark.run(n_requests=a.requests, batch_size=a.batch_size, out_dir=out)
    plot_external(ext, out)
    plot_tamper(tamper, out)
    plot_latency(perf, out)
    plot_breakdown(perf, out)
    plot_storage(perf, out)
    if not a.plots_only:
        write_summary(ext, tamper, perf, out, time.time() - t0)
    write_frontend_snapshot(out)
    print(f"== done -> {out}")


if __name__ == "__main__":
    main()
