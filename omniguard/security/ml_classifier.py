"""Integrity-pinned ONNX prompt-injection classifier (hybrid stage of the engine).

Loading is verify-then-load from memory:
  1. read model.onnx and tokenizer.json fully into memory,
  2. SHA-256 each buffer and compare to configs/model_manifest.json with hmac.compare_digest,
  3. only then build the tokenizer and InferenceSession *from those same verified bytes*,
so there is no time-of-check/time-of-use gap between verification and use.

Inference is deterministic: fixed weights, no sampling, `use_deterministic_compute`, and scores are
quantized to integer milli-units (0..1000) before any threshold comparison, so the value written to the
audit log is exactly the value the decision was made on.

The manifest holds several pinned models (`default` + ablations). The CUDA execution provider is preferred;
CPU is the automatic fallback. Environment switches (used by CI / CPU-only test runs):
    OMNIGUARD_FORCE_CPU=1   never use CUDA
    OMNIGUARD_DISABLE_ML=1  behave as if no model were installed (deterministic-only)
    OMNIGUARD_MODEL=<name>  select a manifest entry other than the default
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from omniguard.config import ROOT, load_json

MODEL_MANIFEST_PATH = ROOT / "configs" / "model_manifest.json"


class ModelIntegrityError(RuntimeError):
    """A model or tokenizer file does not match its pinned SHA-256 digest."""


def verify_bytes(data: bytes, expected_sha256: str, name: str) -> str:
    actual = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual, expected_sha256.lower()):
        raise ModelIntegrityError(f"{name}: sha256 {actual[:16]}... != pinned {expected_sha256[:16]}...")
    return actual


def quantize_milli(p: float) -> int:
    return int(min(1000, max(0, math.floor(p * 1000.0 + 0.5))))


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def load_manifest_entry(name: str | None = None, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return one model's pin entry. Accepts the multi-model layout {default, models{...}} or a single entry."""
    m = manifest if manifest is not None else load_json(MODEL_MANIFEST_PATH)
    if "models" not in m:
        return m  # already a single entry
    key = name or os.environ.get("OMNIGUARD_MODEL") or m["default"]
    entry = dict(m["models"][key])
    entry.setdefault("name", key)
    return entry


@dataclass
class MLResult:
    score_milli: int
    windows: int
    tokenize_ms: float
    infer_ms: float


class PromptInjectionClassifier:
    def __init__(self, manifest: dict[str, Any] | None = None, model_dir: str | Path | None = None,
                 prefer_cuda: bool = True, model_name: str | None = None):
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.manifest = load_manifest_entry(model_name, manifest)
        self.name = self.manifest.get("name", self.manifest.get("model_id", "model"))
        self.model_dir = Path(model_dir) if model_dir else ROOT / self.manifest["local_dir"]
        files = self.manifest["files"]
        t0 = time.perf_counter()
        model_bytes = (self.model_dir / "model.onnx").read_bytes()
        tok_bytes = (self.model_dir / "tokenizer.json").read_bytes()
        self.model_sha256 = verify_bytes(model_bytes, files["model.onnx"]["sha256"], "model.onnx")
        self.tokenizer_sha256 = verify_bytes(tok_bytes, files["tokenizer.json"]["sha256"], "tokenizer.json")
        self.verify_ms = (time.perf_counter() - t0) * 1000

        # The tokenizer.json normalizer (if any) is applied by `tokenizers` itself, e.g. the Horizon models'
        # built-in obfuscation normalizer (tag-character decoding, NFKC, invisible-character stripping).
        self.tokenizer = Tokenizer.from_str(tok_bytes.decode("utf-8"))
        self.tokenizer.no_padding()
        self.tokenizer.no_truncation()
        win = self.manifest.get("window", {})
        self.max_length = int(win.get("max_length", 512))
        self.stride = int(win.get("stride", 384))
        self.max_windows = int(win.get("max_windows", 4))
        # special-token template ([CLS] ... [SEP] or similar) taken from the tokenizer's own post-processor
        empty = self.tokenizer.encode("", add_special_tokens=True).ids
        self.prefix, self.suffix = (empty[:1], empty[1:]) if empty else ([], [])
        self.pad_id = self.tokenizer.token_to_id("[PAD]") or self.tokenizer.token_to_id("<pad>") or 0
        labels = self.manifest.get("labels", {"0": "SAFE", "1": "INJECTION"})
        self.positive_index = int(next(k for k, v in labels.items() if v == self.manifest.get("positive_label", "INJECTION")))

        ort.set_default_logger_severity(3)  # silence benign provider-discovery warnings
        so = ort.SessionOptions()
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        so.use_deterministic_compute = True
        so.log_severity_level = 3
        providers: list[Any] = ["CPUExecutionProvider"]
        if prefer_cuda and not _env_flag("OMNIGUARD_FORCE_CPU") and "CUDAExecutionProvider" in ort.get_available_providers():
            try:
                ort.preload_dlls()
            except Exception:
                pass
            providers = [("CUDAExecutionProvider", {"device_id": 0, "cudnn_conv_algo_search": "DEFAULT"}),
                         "CPUExecutionProvider"]
        t0 = time.perf_counter()
        self.session = ort.InferenceSession(model_bytes, sess_options=so, providers=providers)
        self.load_ms = (time.perf_counter() - t0) * 1000
        del model_bytes
        self.provider = "cuda" if self.session.get_providers()[0] == "CUDAExecutionProvider" else "cpu"
        self.input_names = [i.name for i in self.session.get_inputs()]
        self._lock = threading.Lock()

    @property
    def sha16(self) -> str:
        return self.model_sha256[:16]

    def _windows(self, text: str) -> list[list[int]]:
        ids = self.tokenizer.encode(text, add_special_tokens=False).ids
        body = self.max_length - len(self.prefix) - len(self.suffix)
        starts = range(0, max(len(ids) - body, 0) + 1, self.stride)
        return [[*self.prefix, *ids[s:s + body], *self.suffix] for s in starts][: self.max_windows]

    def score(self, text: str) -> MLResult:
        """Probability of INJECTION, max over up to `max_windows` overlapping windows."""
        import numpy as np

        t0 = time.perf_counter()
        wins = self._windows(text)
        width = max(len(w) for w in wins)
        input_ids = np.full((len(wins), width), self.pad_id, dtype=np.int64)
        attn = np.zeros((len(wins), width), dtype=np.int64)
        for i, w in enumerate(wins):
            input_ids[i, : len(w)] = w
            attn[i, : len(w)] = 1
        feeds = {"input_ids": input_ids, "attention_mask": attn, "token_type_ids": np.zeros_like(input_ids)}
        feeds = {k: v for k, v in feeds.items() if k in self.input_names}
        t1 = time.perf_counter()
        with self._lock:
            logits = self.session.run(None, feeds)[0].astype(np.float64)
        t2 = time.perf_counter()
        logits -= logits.max(axis=1, keepdims=True)
        probs = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
        p = float(probs[:, self.positive_index].max())
        return MLResult(quantize_milli(p), len(wins), (t1 - t0) * 1000, (t2 - t1) * 1000)


_CACHE: dict[tuple[str, str, bool], PromptInjectionClassifier] = {}
_CACHE_LOCK = threading.Lock()


def get_classifier(model_dir: str | Path | None = None, prefer_cuda: bool = True,
                   model_name: str | None = None) -> PromptInjectionClassifier:
    """Process-wide shared instance per model (each model is verified and loaded once)."""
    name = load_manifest_entry(model_name)["name"]
    key = (name, str(model_dir or ""), prefer_cuda and not _env_flag("OMNIGUARD_FORCE_CPU"))
    with _CACHE_LOCK:
        if key not in _CACHE:
            _CACHE[key] = PromptInjectionClassifier(model_dir=model_dir, prefer_cuda=prefer_cuda, model_name=name)
        return _CACHE[key]


def model_available(model_dir: str | Path | None = None, model_name: str | None = None) -> bool:
    if _env_flag("OMNIGUARD_DISABLE_ML"):
        return False
    try:
        m = load_manifest_entry(model_name)
    except (FileNotFoundError, KeyError):
        return False
    d = Path(model_dir) if model_dir else ROOT / m["local_dir"]
    return (d / "model.onnx").exists() and (d / "tokenizer.json").exists()
