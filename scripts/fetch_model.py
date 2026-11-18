"""Fetch the prompt-injection ONNX model at a pinned Hugging Face revision and pin its digests.

    python scripts/fetch_model.py            # download (if missing) and verify against the manifest
    python scripts/fetch_model.py --pin      # (re)write configs/model_manifest.json digests

Model: protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0), official ONNX export.
Only `onnx/model.onnx`, `onnx/tokenizer.json` and `onnx/config.json` are downloaded, at a fixed
commit so the bytes - and therefore the SHA-256 pins - never change underneath us.
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

REPO_ID = "protectai/deberta-v3-base-prompt-injection-v2"
REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
FILES = {"model.onnx": "onnx/model.onnx", "tokenizer.json": "onnx/tokenizer.json", "config.json": "onnx/config.json"}
MODEL_DIR = ROOT / "models" / "deberta-v3-base-prompt-injection-v2"
MANIFEST = CONFIG_DIR / "model_manifest.json"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download() -> None:
    from huggingface_hub import hf_hub_download

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    for local, remote in FILES.items():
        dst = MODEL_DIR / local
        if dst.exists():
            continue
        print(f"downloading {REPO_ID}@{REVISION[:8]}:{remote}")
        src = hf_hub_download(REPO_ID, remote, revision=REVISION)
        shutil.copyfile(src, dst)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin", action="store_true", help="write the digests into configs/model_manifest.json")
    a = ap.parse_args()
    download()
    digests = {name: {"sha256": sha256_file(MODEL_DIR / name), "bytes": (MODEL_DIR / name).stat().st_size}
               for name in ("model.onnx", "tokenizer.json")}
    cfg = json.loads((MODEL_DIR / "config.json").read_text(encoding="utf-8"))
    if a.pin:
        manifest = load_json(MANIFEST) if MANIFEST.exists() else {}
        manifest.update({
            "model_id": REPO_ID,
            "revision": REVISION,
            "license": "apache-2.0",
            "local_dir": str(MODEL_DIR.relative_to(ROOT)).replace("\\", "/"),
            "files": digests,
            "labels": {str(k): v for k, v in cfg.get("id2label", {}).items()},
            "positive_label": "INJECTION",
        })
        save_json(MANIFEST, manifest)
        print(f"pinned -> {MANIFEST}")
    else:
        pinned = load_json(MANIFEST)["files"]
        for name, d in digests.items():
            ok = pinned[name]["sha256"] == d["sha256"]
            print(f"{name:15s} {d['sha256'][:16]}...  {'OK' if ok else 'MISMATCH'}")
            if not ok:
                sys.exit(1)
    for name, d in digests.items():
        print(f"{name}: {d['bytes']:,} bytes  sha256={d['sha256']}")


if __name__ == "__main__":
    main()
