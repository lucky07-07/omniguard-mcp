"""Paths and config loaders shared by every OmniGuard component."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = Path(os.environ.get("OMNIGUARD_CONFIG_DIR", ROOT / "configs"))
CONTRACTS_DIR = ROOT / "contracts"
CONTRACT_BUILD = CONTRACTS_DIR / "build" / "AuditAnchor.json"
RESULTS_DIR = Path(os.environ.get("OMNIGUARD_RESULTS_DIR", ROOT / "results"))

ABAC_POLICY_PATH = CONFIG_DIR / "abac_policies.yaml"
SECURITY_RULES_PATH = CONFIG_DIR / "security_rules.yaml"
PINNED_TOOLS_PATH = CONFIG_DIR / "pinned_tools.json"

SOLC_VERSION = "0.8.24"
DEFAULT_BATCH_SIZE = 16


def load_yaml(path: str | Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_json(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_json(path: str | Path, data: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=False, ensure_ascii=False)
        fh.write("\n")


@lru_cache(maxsize=8)
def _cached_yaml(path: str) -> dict[str, Any]:
    return load_yaml(path)


def security_rules(path: str | Path | None = None) -> dict[str, Any]:
    return _cached_yaml(str(path or SECURITY_RULES_PATH))


def abac_policies(path: str | Path | None = None) -> dict[str, Any]:
    return _cached_yaml(str(path or ABAC_POLICY_PATH))


def pinned_tools(path: str | Path | None = None) -> dict[str, Any]:
    return load_json(path or PINNED_TOOLS_PATH)
