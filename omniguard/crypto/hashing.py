"""Canonical JSON serialization and SHA-256 helpers.

Canonical JSON = sorted keys, no insignificant whitespace, UTF-8, floats
rendered by Python's shortest round-trip repr. Two semantically identical
objects therefore always hash to the same digest.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_hash(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))


def chain_entry_hash(seq_num: int, prev_hash: str, canonical_payload: str) -> str:
    """entry_hash = SHA256(seq_num || prev_hash || canonical_payload).

    seq_num is encoded as an 8-byte big-endian integer and prev_hash as its
    32 raw bytes, so field boundaries are unambiguous.
    """
    if seq_num < 0:
        raise ValueError("seq_num must be non-negative")
    data = seq_num.to_bytes(8, "big") + bytes.fromhex(prev_hash) + canonical_payload.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
