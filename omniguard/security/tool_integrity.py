"""SHA-256 tool-definition pinning and rug-pull detection.

digest = SHA256(canonical_json({name, description, inputSchema}))

A tool whose live definition no longer matches its pinned digest - a changed
description (tool poisoning) or schema (rug pull) - is stripped from
`tools/list` and refused on `tools/call`.

    python -m omniguard.security.tool_integrity --pin     # regenerate configs/pinned_tools.json
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from omniguard.config import PINNED_TOOLS_PATH, load_json, save_json
from omniguard.crypto.hashing import canonical_hash


def tool_digest(tool: dict[str, Any]) -> str:
    return canonical_hash({
        "name": tool["name"],
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema", {}),
    })


@dataclass
class IntegrityResult:
    name: str
    ok: bool
    expected: str | None
    actual: str
    reason: str = ""


class ToolIntegrityRegistry:
    def __init__(self, manifest: dict[str, Any]):
        self.manifest = manifest
        self.tools: dict[str, dict[str, Any]] = manifest.get("tools", {})

    @classmethod
    def load(cls, path: str | Path = PINNED_TOOLS_PATH) -> "ToolIntegrityRegistry":
        return cls(load_json(path))

    def meta(self, name: str) -> dict[str, Any]:
        return self.tools.get(name, {})

    def verify(self, tool: dict[str, Any]) -> IntegrityResult:
        actual = tool_digest(tool)
        pinned = self.tools.get(tool["name"])
        if pinned is None:
            return IntegrityResult(tool["name"], False, None, actual, "tool not pinned")
        if pinned["digest"] != actual:
            return IntegrityResult(tool["name"], False, pinned["digest"], actual, "definition changed since pinning")
        return IntegrityResult(tool["name"], True, pinned["digest"], actual)

    def verify_all(self, tools: list[dict[str, Any]]) -> list[IntegrityResult]:
        return [self.verify(t) for t in tools]


def build_manifest(tools: list[dict[str, Any]], tool_meta: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": 1,
        "algorithm": "sha256(canonical_json({name, description, inputSchema}))",
        "pinned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tools": {
            t["name"]: {
                "digest": tool_digest(t),
                "taint_class": tool_meta[t["name"]]["taint_class"],
                "arg_types": tool_meta[t["name"]]["arg_types"],
                "output_type": tool_meta[t["name"]].get("output_type", "text"),
            }
            for t in tools
        },
    }


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Pin the reference MCP server's tool definitions")
    ap.add_argument("--pin", action="store_true", help="write configs/pinned_tools.json")
    ap.add_argument("--out", default=str(PINNED_TOOLS_PATH))
    args = ap.parse_args(argv)
    from omniguard.tools.sample_mcp_server import TOOL_META, ToolServer

    manifest = build_manifest(ToolServer().list_tools(), TOOL_META)
    if args.pin:
        save_json(args.out, manifest)
        print(f"pinned {len(manifest['tools'])} tools -> {args.out}")
    else:
        for name, entry in manifest["tools"].items():
            print(f"{name:22s} {entry['digest']}")


if __name__ == "__main__":
    main()
