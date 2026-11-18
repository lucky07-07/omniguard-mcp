"""Calibrate the hybrid ML thresholds on the 20% DEV partition only, then freeze them.

Uses exactly the same sha256(text) % 5 == 0 dev split as external_dataset_eval.py, so no held-out
(eval-partition) row is ever scored during calibration. Data: deepset/prompt-injections dev rows
only - jackhhao/jailbreak-classification is excluded because it is part of the classifier's
published training data.

For every dev text the full hybrid pipeline is simulated: a deterministic DENY is a positive
regardless of the model; otherwise the text is routed to the classifier when it is longer than
`min_text_chars`, and predicted positive when score_milli >= t.

    clean threshold     : maximise dev recall subject to precision >= 0.99 (ingress, clean session)
    untrusted threshold : maximise dev recall subject to precision >= 0.95 (egress of untrusted output),
                          and never above the clean threshold
Thresholds are searched in [100, 990] milli. The classifier is almost bimodal, so many thresholds give
identical dev results; the median of that plateau is taken (max-margin) rather than an edge, which
keeps the cut away from both the noise floor and the handful of dev negatives.

    python -m omniguard.evaluation.calibrate_ml [--write]
"""

from __future__ import annotations

import argparse
import re
import warnings
from pathlib import Path

from omniguard.config import RESULTS_DIR, SECURITY_RULES_PATH, save_json
from omniguard.evaluation.external_dataset_eval import STREAMS, partition, stream_rows
from omniguard.models import Decision
from omniguard.security.ml_classifier import get_classifier
from omniguard.security.security_engine import SecurityEngine
from omniguard.security.tool_integrity import ToolIntegrityRegistry

CLEAN_TARGET = 0.99
UNTRUSTED_TARGET = 0.95
SEARCH_RANGE = (100, 990)  # exclude the softmax noise floor and the saturated top


def _metrics(rows: list[tuple[int, bool, int | None]], t: int) -> dict:
    tp = fp = fn = 0
    for y, det, sc in rows:
        pred = det or (sc is not None and sc >= t)
        tp += pred and y
        fp += pred and not y
        fn += (not pred) and y
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"threshold_milli": t, "precision": round(prec, 4), "recall": round(rec, 4), "tp": tp, "fp": fp, "fn": fn}


def _pick(rows: list[tuple[int, bool, int | None]], target: float, cap: int = SEARCH_RANGE[1]) -> dict:
    """Max dev recall s.t. precision >= target; among thresholds dev cannot tell apart (same recall),
    take the median of that plateau (max-margin) instead of an edge."""
    lo, hi = SEARCH_RANGE[0], min(cap, SEARCH_RANGE[1])
    grid = [_metrics(rows, t) for t in range(lo, hi + 1)]
    feasible = [m for m in grid if m["precision"] >= target]
    if not feasible:
        return {**_metrics(rows, hi), "note": "target not reachable; using upper bound"}
    best = max(m["recall"] for m in feasible)
    tied = [m for m in feasible if m["recall"] == best]
    chosen = tied[len(tied) // 2]
    return {**chosen, "plateau": [tied[0]["threshold_milli"], tied[-1]["threshold_milli"]]}


def run(write: bool = False, out_dir: Path = RESULTS_DIR) -> dict:
    warnings.filterwarnings("ignore")
    meta = ToolIntegrityRegistry.load().tools
    det = SecurityEngine(tool_meta=meta)  # deterministic-only reference
    clf = get_classifier()
    min_chars = det.ml_min_chars
    s_in = next(s for s in STREAMS if s.name == "prompt_injection_ingress")
    ingress_rows, egress_rows, seen = [], [], set()
    for text, label in stream_rows(s_in):
        if partition(text) != "dev" or text in seen:
            continue
        seen.add(text)
        env = s_in.wrap(0, text)["params"]
        vi = det.inspect_ingress(env["name"], env["arguments"], set())
        ve = det.inspect_egress("web_fetch", text, set())
        canon = det.canon.canonicalize_string(text).canonical
        score = clf.score(canon).score_milli if det.ml_routable(canon) else None  # same routing as the engine
        ingress_rows.append((label, vi.decision == Decision.DENY, score))
        egress_rows.append((label, ve.decision == Decision.DENY, score))
    clean = _pick(ingress_rows, CLEAN_TARGET)
    untrusted = _pick(egress_rows, UNTRUSTED_TARGET, cap=clean["threshold_milli"])
    routed = sum(1 for r in ingress_rows if r[2] is not None)
    res = {
        "partition": "dev (sha256(text) % 5 == 0)",
        "dataset": "deepset/prompt-injections (train+test, dev rows only)",
        "excluded": {"jackhhao/jailbreak-classification": "listed in the classifier's training data"},
        "rows": len(ingress_rows), "positives": sum(r[0] for r in ingress_rows), "routed_to_ml": routed,
        "model": {"id": clf.manifest["model_id"], "revision": clf.manifest["revision"], "sha16": clf.sha16,
                  "provider": clf.provider},
        "targets": {"clean_precision": CLEAN_TARGET, "untrusted_precision": UNTRUSTED_TARGET},
        "chosen": {"clean": clean, "tainted_untrusted": untrusted},
        "search_range_milli": list(SEARCH_RANGE),
        "rule": "maximise dev recall s.t. precision >= target; ties -> plateau median; untrusted <= clean",
    }
    save_json(out_dir / "ml_calibration.json", res)
    if write:
        txt = SECURITY_RULES_PATH.read_text(encoding="utf-8")
        txt = re.sub(r"(\n    clean: )\d+", rf"\g<1>{clean['threshold_milli']}", txt, count=1)
        txt = re.sub(r"(\n    tainted_untrusted: )\d+", rf"\g<1>{untrusted['threshold_milli']}", txt, count=1)
        SECURITY_RULES_PATH.write_text(txt, encoding="utf-8")
    print(f"[calibrate] dev rows={res['rows']} routed={routed} clean={clean} untrusted={untrusted}")
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="freeze the chosen thresholds into security_rules.yaml")
    a = ap.parse_args()
    run(a.write)


if __name__ == "__main__":
    main()
