"""Fetch prompt-injection ONNX models at pinned Hugging Face revisions and pin their SHA-256 digests.

    python scripts/fetch_model.py                      # default model: download if missing, verify pins
    python scripts/fetch_model.py --model all          # every registered model (ablations included)
    python scripts/fetch_model.py --model NAME --pin   # (re)write that model's digests in the manifest

Only the ONNX graph, tokenizer.json and config.json are downloaded, each at a fixed commit, so the
bytes - and therefore the SHA-256 pins in configs/model_manifest.json - never change underneath us.
Model binaries live in models/ (git-ignored); only their digests are committed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from omniguard.config import CONFIG_DIR, load_json, save_json  # noqa: E402

MANIFEST = CONFIG_DIR / "model_manifest.json"

REGISTRY: dict[str, dict] = {
    # v1.2 default: multilingual mmBERT/ModernBERT guard trained for agent I/O (tool outputs, documents)
    "horizon-guard-base": {
        "repo_id": "Horizon-Labs/prompt-injection-guard-base",
        "revision": "fc071c5754f8cf2edce9dc1d7fd3513ef9287007",
        "license": "apache-2.0",
        "files": {"model.onnx": "onnx/model.onnx", "tokenizer.json": "tokenizer.json", "config.json": "config.json"},
        "local_dir": "models/horizon-guard-base",
        "window": {"max_length": 1024, "stride": 768, "max_windows": 4},
        "training_overlap": ["deepset/prompt-injections:train", "jackhhao/jailbreak-classification:train"],
    },
    # ablation: same recipe, smaller backbone
    "horizon-guard-small": {
        "repo_id": "Horizon-Labs/prompt-injection-guard-small",
        "revision": "2efc2ed5abecd21eb45c2506d231a65d6e392b85",
        "license": "apache-2.0",
        "files": {"model.onnx": "onnx/model.onnx", "tokenizer.json": "tokenizer.json", "config.json": "config.json"},
        "local_dir": "models/horizon-guard-small",
        "window": {"max_length": 1024, "stride": 768, "max_windows": 4},
        "training_overlap": ["deepset/prompt-injections:train", "jackhhao/jailbreak-classification:train"],
    },
    # v1.1 hybrid baseline (kept for the comparison)
    "protectai-deberta-v3-base-v2": {
        "repo_id": "protectai/deberta-v3-base-prompt-injection-v2",
        "revision": "90c9989b1a342275dd0d1a95aad283c04e075671",
        "license": "apache-2.0",
        "files": {"model.onnx": "onnx/model.onnx", "tokenizer.json": "onnx/tokenizer.json", "config.json": "onnx/config.json"},
        "local_dir": "models/deberta-v3-base-prompt-injection-v2",
        "window": {"max_length": 512, "stride": 384, "max_windows": 4},
        "training_overlap": ["jackhhao/jailbreak-classification:all"],
    },
}
DEFAULT = "horizon-guard-base"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def download(name: str) -> Path:
    from huggingface_hub import hf_hub_download

    spec = REGISTRY[name]
    d = ROOT / spec["local_dir"]
    d.mkdir(parents=True, exist_ok=True)
    for local, remote in spec["files"].items():
        if (d / local).exists():
            continue
        print(f"downloading {spec['repo_id']}@{spec['revision'][:8]}:{remote}", flush=True)
        src = hf_hub_download(spec["repo_id"], remote, revision=spec["revision"])
        shutil.copyfile(src, d / local)
    return d


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=None, help=f"registry key or 'all' (default: manifest default / {DEFAULT})")
    ap.add_argument("--pin", action="store_true", help="write digests into configs/model_manifest.json")
    a = ap.parse_args()
    manifest = load_json(MANIFEST) if MANIFEST.exists() else {}
    if "models" not in manifest:
        manifest = {"default": DEFAULT, "models": {}}
    names = list(REGISTRY) if a.model == "all" else [a.model or manifest.get("default", DEFAULT)]
    failed = False
    for name in names:
        spec = REGISTRY[name]
        d = download(name)
        digests = {f: {"sha256": sha256_file(d / f), "bytes": (d / f).stat().st_size} for f in ("model.onnx", "tokenizer.json")}
        cfg = json.loads((d / "config.json").read_text(encoding="utf-8"))
        if a.pin:
            manifest["models"][name] = {
                "model_id": spec["repo_id"], "revision": spec["revision"], "license": spec["license"],
                "local_dir": spec["local_dir"], "files": digests,
                "labels": {str(k): v for k, v in cfg.get("id2label", {}).items()}, "positive_label": "INJECTION",
                "window": spec["window"], "training_overlap": spec["training_overlap"],
            }
            print(f"pinned {name}")
        else:
            pinned = manifest["models"][name]["files"]
            for f, dg in digests.items():
                ok = pinned[f]["sha256"] == dg["sha256"]
                failed |= not ok
                print(f"{name:30s} {f:15s} {dg['sha256'][:16]}...  {'OK' if ok else 'MISMATCH'}")
    if a.pin:
        save_json(MANIFEST, manifest)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
