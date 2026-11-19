"""Fold the local hybrid-ML run into results.json and draw the high-resolution ablation charts.

    python benchmarks/make_charts.py

Inputs : benchmarks/results.json                   (live Render API run, deterministic engine; Render's free tier has
                                                     no room for the 0.6 GB ONNX guard model)
         benchmarks/results_local_hybrid_ml.json   (same 100 cases, same API code, in-process with the pinned Horizon
                                                     guard-base ONNX model on the local RTX 2060)
Outputs: results.json gains `hybrid_ml` and two extra category rows; charts in benchmarks/charts/ (PNG, 300 dpi + SVG)
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent
CH = HERE / "charts"
MODES = ("A", "B", "C")
COL = {"A": "#9aa3ad", "B": "#d08a3c", "C": "#1f7a6d"}
NAME = {"A": "A · unprotected", "B": "B · ingress + mutable log", "C": "C · OmniGuard"}

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.titleweight": "bold", "axes.titlesize": 13})


def save(fig, name: str) -> None:
    fig.tight_layout()
    fig.savefig(CH / f"{name}.png", dpi=300)
    fig.savefig(CH / f"{name}.svg")
    plt.close(fig)


def bars(ax, cats: dict, keys: list[str]) -> None:
    w = 0.26
    for i, m in enumerate(MODES):
        xs = [k + (i - 1) * w for k in range(len(keys))]
        vs = [cats[k][m] or 0 for k in keys]
        b = ax.bar(xs, vs, w, color=COL[m], label=NAME[m])
        ax.bar_label(b, labels=[f"{v:g}" for v in vs], fontsize=8, padding=2)
    ax.set_xticks(range(len(keys)), [cats[k]["label"].replace(" / ", " /\n") + f"\n{cats[k]['source']}\nn={cats[k]['n']}" for k in keys], fontsize=9)
    ax.set_ylim(0, 112)


def main() -> None:
    CH.mkdir(exist_ok=True)
    live = json.loads((HERE / "results.json").read_text(encoding="utf-8"))
    hyb_path = HERE / "results_local_hybrid_ml.json"
    if hyb_path.exists():
        hyb = json.loads(hyb_path.read_text(encoding="utf-8"))
        live["hybrid_ml"] = {k: hyb[k] for k in ("run", "summary", "categories", "latency_ms")}
        hc = hyb["categories"]
        live["categories"]["benign_ml"] = {**hc["benign"], "label": "Benign tasks + hybrid ML",
                                          "source": "AgentDojo · local GPU run"}
        live["categories"]["injection_ml"] = {**hc["injection"], "label": "Prompt injection + hybrid ML",
                                             "source": "AgentDojo + MSB · local GPU run"}
        (HERE / "results.json").write_text(json.dumps(live, indent=1), encoding="utf-8")
    cats = live["categories"]

    fig, axes = plt.subplots(1, 2, figsize=(13, 5.4), gridspec_kw={"width_ratios": [3, 2.2]})
    bars(axes[0], cats, ["injection", "poisoning", "chain"])
    axes[0].set_ylabel("attack success rate (%)  ↓ better")
    axes[0].set_title("Attacks that reached the tool (live Render API)")
    bars(axes[1], cats, ["benign", "tamper"])
    axes[1].set_ylabel("% ↑ better")
    axes[1].set_title("Benign utility · tamper detection")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=3, frameon=False)
    fig.tight_layout(rect=(0, 0.07, 1, 1))
    fig.savefig(CH / "ablation_modes.png", dpi=300)
    fig.savefig(CH / "ablation_modes.svg")
    plt.close(fig)

    if "hybrid_ml" in live:
        h = live["hybrid_ml"]["categories"]
        fig, ax = plt.subplots(figsize=(8.5, 4.8))
        labels = ["Injection ASR ↓", "Benign FPR ↓"]
        det = [cats["injection"]["C"], 100 - cats["benign"]["C"]]
        ml = [h["injection"]["C"], 100 - h["benign"]["C"]]
        x = range(2)
        b1 = ax.bar([i - 0.18 for i in x], det, 0.36, color="#d08a3c", label="Mode C, deterministic engine (live Render)")
        b2 = ax.bar([i + 0.18 for i in x], ml, 0.36, color="#1f7a6d", label="Mode C + pinned Horizon guard ONNX (RTX 2060)")
        ax.bar_label(b1, fmt="%g", padding=2)
        ax.bar_label(b2, fmt="%g", padding=2)
        ax.set_xticks(list(x), labels)
        ax.set_ylim(0, 112)
        ax.set_ylabel("%")
        ax.set_title("25 real injections · 30 real benign tasks")
        ax.legend(frameon=False, loc="upper right", fontsize=9)
        save(fig, "engine_tradeoff")

    L = live["latency_ms"]
    fig, ax = plt.subplots(figsize=(8.5, 4.8))
    for i, qn in enumerate(("p50", "p95")):
        vs = [L[m][qn] for m in MODES]
        b = ax.bar([k + (i - 0.5) * 0.36 for k in range(3)], vs, 0.36, color=["#7fb3a9", "#1f7a6d"][i], label=qn)
        ax.bar_label(b, labels=[f"{v:.2f}" for v in vs], fontsize=9, padding=2)
    ax.set_yscale("log")
    ax.set_xticks(range(3), [NAME[m] for m in MODES])
    ax.set_ylabel("server-side gateway time (ms, log scale)")
    ax.set_title("Latency per call, live Render API")
    ax.legend(frameon=False, loc="upper left")
    ax.set_ylim(top=L["C"]["p95"] * 3)
    ax.text(1.62, L["C"]["p95"] * 0.6, "C p95 = calls that seal a\nMerkle batch and send the\nanchor transaction", ha="right", va="top", fontsize=8, color="#555")
    save(fig, "latency_p50_p95")

    rows = live["tamper_cases"]
    attacks = list(dict.fromkeys(r["attack"] for r in rows))
    fig, ax = plt.subplots(figsize=(8.5, 4.2))
    for i, m in enumerate(MODES):
        vs = [100 * sum(r["detected"][m] for r in rows if r["attack"] == a) / sum(r["attack"] == a for r in rows) for a in attacks]
        b = ax.bar([k + (i - 1) * 0.26 for k in range(len(attacks))], vs, 0.26, color=COL[m], label=NAME[m])
        ax.bar_label(b, fmt="%g", fontsize=8, padding=2)
    ax.set_xticks(range(len(attacks)), [a.replace("_", " ") for a in attacks])
    ax.set_ylim(0, 115)
    ax.set_ylabel("detected (%)")
    ax.set_title("Post-hoc tampering of anchored records, by attack")
    ax.legend(frameon=False, fontsize=9, ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.12))
    save(fig, "tamper_by_attack")
    print(sorted(p.name for p in CH.iterdir()))


if __name__ == "__main__":
    main()
