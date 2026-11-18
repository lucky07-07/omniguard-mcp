"""Calibrate the hybrid two-tier cascade thresholds on a contamination-free VALIDATION set, then freeze them.

Validation set (never touches the 80% eval partition):
    dev partition (sha256(text) % 5 == 0)  AND  the dataset's official TEST split
    - deepset/prompt-injections test  -> ingress (write_file content) and egress (web_fetch output)
    - jackhhao/jailbreak-classification test -> ingress
The Horizon guard models were trained on the deepset and jackhhao TRAIN splits (model card), so restricting
validation to TEST-split rows keeps their training data out of threshold selection.

The full hybrid pipeline is simulated for every validation row: a deterministic DENY is positive regardless of
the model; otherwise canonicalized prose segments are scored and compared with the tier threshold:
    clean     - CLEAN session and deterministic risk == 0
    elevated  - untrusted tool output (egress) or any weighted deterministic rule fired (ingress)
Sweep: tau_clean, tau_elevated in [0.15, 0.55] step 0.01 with tau_elevated <= tau_clean. Pairs within 0.005 F1
of the best (about one validation example) count as tied; among them the highest-precision pairs are kept and
the median of that plateau is chosen, then frozen.

    python -m omniguard.evaluation.calibrate_ml [--model horizon-guard-base] [--write]
"""

from __future__ import annotations

import argparse
import re
import warnings
from pathlib import Path

from omniguard.config import RESULTS_DIR, SECURITY_RULES_PATH, load_json, load_yaml, save_json
from omniguard.evaluation.external_dataset_eval import STREAMS, partition, stream_rows
from omniguard.models import Decision
from omniguard.security.ml_classifier import get_classifier
from omniguard.security.security_engine import SecurityEngine
from omniguard.security.tool_integrity import ToolIntegrityRegistry

GRID = range(150, 551, 10)  # milli
VALIDATION_STREAMS = ("prompt_injection_ingress", "prompt_injection_egress", "jailbreak_ingress")


def collect(model: str) -> list[dict]:
    """One record per validation row: label, deterministic decision/risk, routed?, ML score, tier."""
    det = SecurityEngine(rules=load_yaml(SECURITY_RULES_PATH), tool_meta=ToolIntegrityRegistry.load().tools)
    clf = get_classifier(model_name=model)
    rows = []
    for name in VALIDATION_STREAMS:
        s = next(x for x in STREAMS if x.name == name)
        seen = set()
        for text, label, split in stream_rows(s):
            if split != "test" or partition(text) != "dev" or text in seen:
                continue
            seen.add(text)
            if s.direction == "ingress":
                p = s.wrap(0, text)["params"]
                v = det.inspect_ingress(p["name"], p["arguments"], set())
                elevated = v.risk_score > 0
            else:
                v = det.inspect_egress("web_fetch", text, set())
                elevated = True  # untrusted tool output
            canon = det.canon.canonicalize_string(text).canonical
            segs = det.ml_segments(canon)
            score = max(clf.score(t).score_milli for t in segs) if segs else None
            rows.append({"stream": name, "label": label, "det_deny": v.decision == Decision.DENY,
                         "elevated": elevated, "score": score})
    return rows


def _f1(rows: list[dict], tc: int, te: int) -> dict:
    tp = fp = fn = tn = 0
    for r in rows:
        thr = te if r["elevated"] else tc
        pred = r["det_deny"] or (r["score"] is not None and r["score"] >= thr)
        y = r["label"]
        tp += pred and y
        fp += pred and not y
        fn += (not pred) and y
        tn += (not pred) and not y
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    return {"clean": tc, "elevated": te, "f1": round(2 * p * rc / (p + rc), 4) if p + rc else 0.0,
            "precision": round(p, 4), "recall": round(rc, 4), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


F1_TOLERANCE = 0.005  # ~ one validation example on ~86 rows


def sweep(rows: list[dict]) -> tuple[dict, list[dict]]:
    """Pairs within F1_TOLERANCE of the best are statistically indistinguishable on a validation set this
    small; among them prefer the highest precision (fewer false alarms), then take the plateau median."""
    grid = [_f1(rows, tc, te) for tc in GRID for te in GRID if te <= tc]
    best = max(g["f1"] for g in grid)
    near = [g for g in grid if g["f1"] >= best - F1_TOLERANCE]
    top_p = max(g["precision"] for g in near)
    tied = sorted([g for g in near if g["precision"] == top_p], key=lambda g: (g["clean"], g["elevated"]))
    return {**tied[len(tied) // 2], "tied_pairs": len(tied), "best_f1_on_grid": best}, grid


def run(model: str = "horizon-guard-base", write: bool = False, out_dir: Path = RESULTS_DIR) -> dict:
    warnings.filterwarnings("ignore")
    rows = collect(model)
    chosen, grid = sweep(rows)
    clf = get_classifier(model_name=model)
    entry = {
        "model": {"name": model, "id": clf.manifest["model_id"], "revision": clf.manifest["revision"],
                  "sha16": clf.sha16, "provider": clf.provider},
        "validation_set": "dev partition AND official test split (deepset ingress+egress, jackhhao ingress)",
        "rows": len(rows), "positives": sum(r["label"] for r in rows),
        "routed_to_ml": sum(r["score"] is not None for r in rows),
        "per_stream_rows": {n: sum(r["stream"] == n for r in rows) for n in VALIDATION_STREAMS},
        "grid_milli": [GRID.start, GRID.stop - 1, GRID.step],
        "rule": ("max pooled F1 over tau_elevated <= tau_clean; pairs within 0.005 F1 of the best are tied; "
                 "among tied pairs take the highest precision, then the plateau median"),
        "rule_note": ("the 0.005 tolerance was added after the first sweep picked the grid edge (0.15/0.15) on a "
                      "0.001 F1 margin (one validation example); decided on validation data only, before any eval run"),
        "chosen": chosen,
        "deterministic_only_on_validation": _f1(rows, 10**6, 10**6),
        "f1_surface": grid,
    }
    path = out_dir / "ml_calibration.json"
    allres = load_json(path) if path.exists() else {}
    if "models" not in allres:
        allres = {"models": {}, "legacy_v1.1_protectai": allres or None}
    allres["models"][model] = entry
    save_json(path, allres)
    if write:
        txt = SECURITY_RULES_PATH.read_text(encoding="utf-8")
        txt = re.sub(r"(\n    clean: )\d+", rf"\g<1>{chosen['clean']}", txt, count=1)
        txt = re.sub(r"(\n    elevated: )\d+", rf"\g<1>{chosen['elevated']}", txt, count=1)
        SECURITY_RULES_PATH.write_text(txt, encoding="utf-8")
    print(f"[calibrate] {model}: rows={entry['rows']} routed={entry['routed_to_ml']} chosen={chosen} "
          f"det-only={entry['deterministic_only_on_validation']}")
    return entry


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="horizon-guard-base")
    ap.add_argument("--write", action="store_true", help="freeze the chosen pair into security_rules.yaml")
    a = ap.parse_args()
    run(a.model, a.write)


if __name__ == "__main__":
    main()
