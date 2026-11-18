"""Single-command runner for every OmniGuard-MCP experiment.

    python scripts/run_all_experiments.py [--max-samples 500] [--trials 5] [--requests 500]

Produces in results/:
    external_dataset_eval.json / .md
    tamper_detection_r1_r2_r3.json / .md
    performance_storage_r1_r2_r3.json / .md
    *.png summary figures
    SUMMARY.md
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
    R = perf["regimes"]
    regs = list(R)
    stats = ["mean", "p50", "p95", "p99"]
    fig, ax = plt.subplots(figsize=(8.5, 4.6))
    w = 0.8 / len(regs)
    x = np.arange(len(stats))
    for i, g in enumerate(regs):
        vals = [R[g]["e2e_latency_ms"][s] for s in stats]
        bar(ax, x + (i - (len(regs) - 1) / 2) * w, vals, w, REGIME_COLOR[g], g)
    ax.set_yscale("log")
    ax.set_xticks(x, ["Mean", "p50", "p95", "p99"])
    ax.set_ylabel("End-to-end latency per tools/call (ms, log scale)")
    ax.set_title(f"Request latency, M={perf['config']['requests']}, B={perf['config']['batch_size']}", loc="left")
    ax.legend(ncol=len(regs), loc="upper left")
    fig.tight_layout()
    fig.savefig(out / "latency_r1_r2_r3.png", dpi=160)
    plt.close(fig)


def plot_breakdown(perf: dict, out: Path) -> None:
    R = perf["regimes"]
    regs = list(R)
    stages = [("tool_integrity", "Tool integrity"), ("security_engine", "Security engine"),
              ("downstream_tool", "Downstream tool"), ("hash_chain", "Hash chain"),
              ("merkle_build_amortized", "Merkle build (amortized)"), ("anchor_tx_amortized", "Anchor tx (amortized)")]
    fig, ax = plt.subplots(figsize=(8.5, 3.8))
    left = np.zeros(len(regs))
    for j, (k, name) in enumerate(stages):
        vals = np.array([R[g]["stage_ms_mean_per_request"][k] for g in regs])
        ax.barh(regs, vals, left=left, color=SERIES[j], label=name, edgecolor=SURFACE, linewidth=1.5, height=0.6)
        left += vals
    rest = np.array([R[g]["e2e_latency_ms"]["mean"] for g in regs]) - left
    ax.barh(regs, np.clip(rest, 0, None), left=left, color="#c9c8c2", label="SQLite write + other",
            edgecolor=SURFACE, linewidth=1.5, height=0.6)
    xmax = 1.0
    for i, g in enumerate(regs):
        total = R[g]["e2e_latency_ms"]["mean"]
        if total > xmax:
            ax.text(xmax * 0.985, i, f"clipped: total {total:.2f} ms ", va="center", ha="right", color="#ffffff",
                    fontsize=9, fontweight="bold")
        else:
            ax.text(total, i, f"  {total:.2f} ms", va="center", color=INK2)
    ax.set_xlim(0, xmax)
    ax.invert_yaxis()
    ax.set_xlabel("Mean ms per request (linear, axis clipped at 1 ms)")
    ax.set_title("Where the time goes (mean per request)", loc="left")
    ax.legend(ncol=3, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.22))
    fig.tight_layout()
    fig.savefig(out / "latency_breakdown_r1_r2_r3.png", dpi=160, bbox_inches="tight")
    plt.close(fig)


def plot_storage(perf: dict, out: Path) -> None:
    R = perf["regimes"]
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


def plot_external(ext: dict, out: Path) -> None:
    ok = {k: v for k, v in ext["streams"].items() if v.get("status") == "ok"}
    if not ok:
        return
    metrics = [("precision", "Precision"), ("recall_tpr", "Recall"), ("f1", "F1")]
    fig, ax = plt.subplots(figsize=(9, 4.4))
    x = np.arange(len(ok))
    w = 0.26
    for i, (k, name) in enumerate(metrics):
        vals = [v[k] for v in ok.values()]
        b = bar(ax, x + (i - 1) * w, vals, w, SERIES[i], name)
        if k == "f1":
            ax.bar_label(b, fmt="%.2f", color=INK2, fontsize=8, padding=2)
    ax.set_xticks(x, [k.replace("_", "\n") for k in ok], fontsize=8.5)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel("score (held-out eval partition)")
    ax.set_title("Deterministic engine: external validation (no ML)", loc="left", pad=22)
    ax.legend(ncol=3, loc="lower right", bbox_to_anchor=(1.0, 1.0), fontsize=9)
    fig.tight_layout()
    fig.savefig(out / "external_dataset_eval.png", dpi=160)
    plt.close(fig)


def write_summary(ext: dict, tamper: dict, perf: dict, out: Path, elapsed: float) -> None:
    lines = ["# OmniGuard-MCP - experiment summary", "",
             f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} on {platform.platform()} / Python {platform.python_version()}, "
             f"total runtime {elapsed / 60:.1f} min.", "", "## External validation (held-out partition)", "",
             "| Stream | n | Precision | Recall | F1 | FPR |", "|---|---|---|---|---|---|"]
    for k, v in ext["streams"].items():
        if v.get("status") == "ok":
            lines.append(f"| {k} | {v['samples']} | {v['precision']:.3f} | {v['recall_tpr']:.3f} | {v['f1']:.3f} | {v['fpr']:.3f} |")
        else:
            lines.append(f"| {k} | - | {v.get('status')} | | | |")
    lines += ["", "## Tamper detection (trials detected)", "", "| Regime | Detected | Rate |", "|---|---|---|"]
    for g in ("R1", "R2", "R3"):
        rr = [r for r in tamper["rows"] if r["regime"] == g]
        d, t = sum(r["detected_trials"] for r in rr), sum(r["trials"] for r in rr)
        lines.append(f"| {g} | {d}/{t} | {100 * d / t:.1f}% |")
    lines += ["", "## Latency and storage", "", "| Regime | Mean ms | p95 ms | p99 ms | Bytes/event | Gas/event |",
              "|---|---|---|---|---|---|"]
    for g, r in perf["regimes"].items():
        e = r["e2e_latency_ms"]
        lines.append(f"| {g} | {e['mean']:.3f} | {e['p95']:.3f} | {e['p99']:.3f} | {r['storage']['bytes_per_event']} | "
                     f"{r['storage']['onchain_gas_per_event']} |")
    lines += ["", "Details: `external_dataset_eval.md`, `tamper_detection_r1_r2_r3.md`, `performance_storage_r1_r2_r3.md`."]
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


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
    print(f"== done -> {out}")


if __name__ == "__main__":
    main()
