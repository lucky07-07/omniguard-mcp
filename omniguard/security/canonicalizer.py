"""Stage 1: recursive canonicalization and de-obfuscation.

Every string is normalised (Unicode NFKC, zero-width characters removed) and
then repeatedly decoded - URL percent-encoding, HTML entities, `\\xNN` /
`\\uNNNN` escapes, whole-string Base64 and hex - until a fixed point or
`max_depth` is reached. Base64 tokens embedded inside a larger string are
decoded into extra *views*. Downstream analyzers inspect every view, so an
attacker cannot hide a payload behind an encoding layer.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠⁡⁢⁣⁤﻿­"), None)
PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
HTML_ENTITY_RE = re.compile(r"&(#\d{1,7}|#[xX][0-9A-Fa-f]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})|\\U([0-9A-Fa-f]{8})")
B64_WHOLE_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
B64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
HEX_WHOLE_RE = re.compile(r"^(0x)?[0-9A-Fa-f]+$")


def _printable(text: str, ratio: float) -> bool:
    if not text:
        return False
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return ok / len(text) >= ratio


def _try_b64(token: str, min_len: int, ratio: float) -> str | None:
    t = token.strip()
    if len(t) < min_len or not B64_WHOLE_RE.match(t):
        return None
    # A Base64 payload of real text almost always mixes cases or digits; pure
    # lowercase words would otherwise decode into noise and be rejected anyway.
    if t.isalpha() and (t.islower() or t.isupper()):
        return None
    t = t.replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        raw = base64.b64decode(t, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if _printable(text, ratio) and len(text.strip()) >= 4 else None


def _try_hex(token: str, min_len: int, ratio: float) -> str | None:
    t = token.strip()
    if len(t) < min_len or not HEX_WHOLE_RE.match(t):
        return None
    t = t[2:] if t.lower().startswith("0x") else t
    if len(t) % 2:
        return None
    try:
        text = bytes.fromhex(t).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _printable(text, ratio) else None


def _decode_escapes(s: str) -> str:
    def rep(m: re.Match) -> str:
        code = m.group(1) or m.group(2) or m.group(3)
        try:
            return chr(int(code, 16))
        except ValueError:
            return m.group(0)

    return ESCAPE_RE.sub(rep, s)


@dataclass
class CanonicalString:
    original: str
    canonical: str
    views: list[str]
    layers: list[str] = field(default_factory=list)

    @property
    def obfuscation_depth(self) -> int:
        return len([l for l in self.layers if l != "nfkc"])


class RecursiveCanonicalizer:
    def __init__(self, max_depth: int = 6, min_base64_len: int = 16, min_hex_len: int = 16,
                 printable_ratio: float = 0.9):
        self.max_depth = max_depth
        self.min_b64 = min_base64_len
        self.min_hex = min_hex_len
        self.ratio = printable_ratio

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> "RecursiveCanonicalizer":
        c = cfg.get("canonicalizer", {})
        return cls(c.get("max_depth", 6), c.get("min_base64_len", 16), c.get("min_hex_len", 16),
                   c.get("printable_ratio", 0.9))

    def _one_pass(self, s: str, layers: list[str]) -> str:
        out = unicodedata.normalize("NFKC", s).translate(ZERO_WIDTH)
        if out != s:
            layers.append("nfkc")
        if PCT_RE.search(out):
            dec = unquote(out)
            if dec != out:
                layers.append("url")
                out = dec
        if HTML_ENTITY_RE.search(out):
            dec = html.unescape(out)
            if dec != out:
                layers.append("html")
                out = dec
        if ESCAPE_RE.search(out):
            dec = _decode_escapes(out)
            if dec != out:
                layers.append("escape")
                out = dec
        b64 = _try_b64(out, self.min_b64, self.ratio)
        if b64 is not None:
            layers.append("base64")
            return b64
        hx = _try_hex(out, self.min_hex, self.ratio)
        if hx is not None:
            layers.append("hex")
            return hx
        return out

    def canonicalize_string(self, s: str, _depth: int = 0) -> CanonicalString:
        layers: list[str] = []
        cur = s
        for _ in range(self.max_depth):
            nxt = self._one_pass(cur, layers)
            if nxt == cur:
                break
            cur = nxt
        views = [s] if cur == s else [s, cur]
        # Embedded Base64 tokens (e.g. "please run aWdub3JlIGFsbC4uLg==") become extra views.
        if _depth < 2:
            for tok in B64_TOKEN_RE.findall(cur):
                dec = _try_b64(tok, self.min_b64, self.ratio)
                if dec is None:
                    continue
                inner = self.canonicalize_string(dec, _depth + 1)
                layers.append("base64_embedded")
                layers.extend(inner.layers)
                views.extend(v for v in inner.views if v not in views)
        return CanonicalString(original=s, canonical=cur, views=views, layers=layers)

    def canonicalize(self, value: Any) -> tuple[Any, dict[str, CanonicalString]]:
        """Canonicalize any JSON value. Returns (canonical_value, {json_path: CanonicalString})."""
        found: dict[str, CanonicalString] = {}

        def walk(v: Any, path: str) -> Any:
            if isinstance(v, str):
                cs = self.canonicalize_string(v)
                found[path] = cs
                return cs.canonical
            if isinstance(v, dict):
                return {str(k): walk(x, f"{path}.{k}" if path else str(k)) for k, x in v.items()}
            if isinstance(v, (list, tuple)):
                return [walk(x, f"{path}[{i}]") for i, x in enumerate(v)]
            return v

        return walk(value, ""), found
