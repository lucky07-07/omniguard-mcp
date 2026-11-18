"""Multi-stage deterministic security engine (ingress + egress).

    Stage 1  RecursiveCanonicalizer       (canonical views of every string)
    Stage 2  structural analyzers          (path / url / shell / sql by argument type)
             + compiled threat signatures  (prompt injection, generic payloads)
    Stage 3  taint-aware flow checks       (TAINTED_SENSITIVE -> no egress)
    Stage 4  entropy DLP                   (secrets in args to outbound tools / in outputs)
    Stage 5  weighted risk score           -> deterministic decision trace

risk = (sum of the max weight of each distinct triggered rule) x taint multiplier
DENY iff risk >= deny_threshold. The same input in the same taint state always
yields the same decision and the same canonical_input_hash.
"""

from __future__ import annotations

import time
from typing import Any

from omniguard.config import security_rules
from omniguard.crypto.hashing import canonical_hash
from omniguard.models import Decision, RuleHit, SecurityVerdict, TaintLabel, ToolTaintClass
from omniguard.security.analyzers import (
    EntropyDLP,
    PathJail,
    ShellAnalyzer,
    SQLAnalyzer,
    SSRFValidator,
    compile_signatures,
    match_signatures,
)
from omniguard.security.canonicalizer import RecursiveCanonicalizer


class SecurityEngine:
    def __init__(self, rules: dict[str, Any] | None = None, tool_meta: dict[str, dict[str, Any]] | None = None):
        self.cfg = rules if rules is not None else security_rules()
        self.tool_meta = tool_meta or {}
        sc = self.cfg.get("scoring", {})
        self.threshold = float(sc.get("deny_threshold", 1.0))
        self.taint_mult = {k: float(v) for k, v in (sc.get("taint_multipliers") or {}).items()}
        self.untrusted_output_mult = float(sc.get("untrusted_output_multiplier", 1.5))
        self.weights = {k: float(v) for k, v in (self.cfg.get("rules") or {}).items()}
        an = self.cfg.get("analyzers", {})
        self.canon = RecursiveCanonicalizer.from_config(self.cfg)
        self.jail = PathJail(an.get("path", {}).get("workspace_roots", ["/workspace"]),
                             an.get("path", {}).get("sensitive_globs", []))
        net = an.get("network", {})
        self.ssrf = SSRFValidator(net.get("allowed_schemes", ["http", "https"]),
                                  net.get("blocked_hostnames", []), net.get("blocked_host_suffixes", []))
        self.shell = ShellAnalyzer(an.get("shell", {}).get("dangerous_binaries", []))
        self.sql = SQLAnalyzer(an.get("sql", {}).get("sensitive_table_prefixes", []))
        d = self.cfg.get("dlp", {})
        self.dlp = EntropyDLP(d.get("prefixed_min_entropy", 3.0), d.get("generic_min_entropy", 3.5),
                              d.get("high_entropy_min_length", 32), d.get("high_entropy_threshold", 4.5))
        self.signatures = compile_signatures(self.cfg)

    # ------------------------------------------------------------------ helpers
    def _w(self, rule_id: str, default: float = 0.5) -> float:
        return self.weights.get(rule_id, default)

    def multiplier(self, taint: set[TaintLabel]) -> float:
        if not taint:
            return self.taint_mult.get("CLEAN", 1.0)
        return max(self.taint_mult.get(l.value, 1.0) for l in taint)

    def arg_type(self, tool: str, arg_path: str) -> str:
        top = arg_path.split(".")[0].split("[")[0]
        return (self.tool_meta.get(tool, {}).get("arg_types") or {}).get(top, "text")

    def tool_class(self, tool: str) -> ToolTaintClass:
        return ToolTaintClass(self.tool_meta.get(tool, {}).get("taint_class", "neutral"))

    def _score(self, hits: list[RuleHit], mult: float) -> tuple[float, bool]:
        best: dict[str, float] = {}
        for h in hits:
            best[h.rule_id] = max(best.get(h.rule_id, 0.0), h.weight)
        hard = any(w >= self.threshold for w in best.values())
        return round(sum(best.values()) * mult, 4), hard

    # ------------------------------------------------------------------ ingress
    def inspect_ingress(self, tool: str, args: dict[str, Any], taint: set[TaintLabel] | None = None,
                        tool_class: ToolTaintClass | None = None) -> SecurityVerdict:
        taint = taint or set()
        tool_class = tool_class or self.tool_class(tool)
        timings: dict[str, float] = {}
        hits: list[RuleHit] = []

        t0 = time.perf_counter()
        canonical_args, strings = self.canon.canonicalize(args or {})
        layers = sorted({l for cs in strings.values() for l in cs.layers})
        timings["canonicalize_ms"] = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        for path, cs in strings.items():
            kind = self.arg_type(tool, path)
            findings = []
            if kind == "path":
                findings = self.jail.analyze(cs.canonical)
            elif kind == "url":
                findings = self.ssrf.analyze(cs.canonical)
            elif kind == "shell":
                findings = self.shell.analyze(cs.canonical)
            elif kind == "sql":
                findings = self.sql.analyze(cs.canonical)
            for f in findings:
                hits.append(RuleHit(rule_id=f.rule_id, weight=self._w(f.rule_id, 1.0), stage="structural",
                                    argument=path, detail=f.detail))
            if cs.obfuscation_depth >= 2:
                hits.append(RuleHit(rule_id="OBFUSCATION_MULTILAYER", weight=self._w("OBFUSCATION_MULTILAYER"),
                                    stage="canonicalize", argument=path, detail="+".join(cs.layers)))
            elif "base64" in cs.layers or "base64_embedded" in cs.layers:
                hits.append(RuleHit(rule_id="OBFUSCATION_BASE64_PAYLOAD",
                                    weight=self._w("OBFUSCATION_BASE64_PAYLOAD"), stage="canonicalize",
                                    argument=path, detail="+".join(cs.layers)))
        timings["structural_ms"] = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        for path, cs in strings.items():
            for sig, snippet in match_signatures(self.signatures, cs.views):
                hits.append(RuleHit(rule_id=sig.rule_id, weight=sig.weight, stage=f"signature:{sig.family}",
                                    argument=path, detail=snippet))
        timings["signatures_ms"] = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        if tool_class == ToolTaintClass.OUTBOUND_EGRESS:
            for path, cs in strings.items():
                secrets = self.dlp.scan(cs.canonical)
                if secrets:
                    hits.append(RuleHit(rule_id="SECRET_TO_OUTBOUND_TOOL", weight=self._w("SECRET_TO_OUTBOUND_TOOL", 1.0),
                                        stage="dlp", argument=path,
                                        detail=",".join(sorted({s.rule_id for s in secrets}))))
            if TaintLabel.TAINTED_SENSITIVE in taint:
                hits.append(RuleHit(rule_id="TAINT_SENSITIVE_TO_EGRESS", weight=self._w("TAINT_SENSITIVE_TO_EGRESS", 1.0),
                                    stage="taint", detail="sensitive session -> outbound tool"))
        timings["dlp_taint_ms"] = (time.perf_counter() - t0) * 1000

        risk, hard = self._score(hits, self.multiplier(taint))
        decision = Decision.DENY if hard or risk >= self.threshold else Decision.ALLOW
        return SecurityVerdict(
            direction="ingress",
            decision=decision,
            risk_score=risk,
            triggered_rules=hits,
            taint_state=sorted(taint, key=lambda l: l.value) or [TaintLabel.CLEAN],
            canonical_input_hash=canonical_hash({"tool": tool, "arguments": canonical_args}),
            encoding_layers=layers,
            stage_ms=timings,
        )

    # ------------------------------------------------------------------ egress
    def inspect_egress(self, tool: str, output: str, taint: set[TaintLabel] | None = None,
                       tool_class: ToolTaintClass | None = None) -> SecurityVerdict:
        taint = taint or set()
        tool_class = tool_class or self.tool_class(tool)
        timings: dict[str, float] = {}
        hits: list[RuleHit] = []

        t0 = time.perf_counter()
        cs = self.canon.canonicalize_string(output or "")
        timings["canonicalize_ms"] = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        for sig, snippet in match_signatures(self.signatures, cs.views):
            hits.append(RuleHit(rule_id=sig.rule_id, weight=sig.weight, stage=f"egress_signature:{sig.family}",
                                detail=snippet))
        if cs.obfuscation_depth >= 2 and hits:
            hits.append(RuleHit(rule_id="OBFUSCATION_MULTILAYER", weight=self._w("OBFUSCATION_MULTILAYER"),
                                stage="canonicalize", detail="+".join(cs.layers)))
        timings["signatures_ms"] = (time.perf_counter() - t0) * 1000

        mult = self.multiplier(taint)
        if tool_class == ToolTaintClass.UNTRUSTED_EXTERNAL:
            mult = max(mult, self.untrusted_output_mult)
        risk, hard = self._score(hits, mult)

        t0 = time.perf_counter()
        secrets = self.dlp.scan(output or "")
        timings["dlp_ms"] = (time.perf_counter() - t0) * 1000

        redacted = None
        if hard or risk >= self.threshold:
            decision = Decision.DENY
        elif secrets:
            decision = Decision.REDACT
            redacted = self.dlp.redact(output, secrets)
        else:
            decision = Decision.ALLOW
        for s in secrets:
            hits.append(RuleHit(rule_id=s.rule_id, weight=0.0, stage="egress_dlp",
                                detail=f"span {s.start}-{s.end}, entropy {s.entropy:.2f}"))
        return SecurityVerdict(
            direction="egress",
            decision=decision,
            risk_score=risk,
            triggered_rules=hits,
            taint_state=sorted(taint, key=lambda l: l.value) or [TaintLabel.CLEAN],
            canonical_input_hash=canonical_hash({"tool": tool, "output": cs.canonical}),
            encoding_layers=sorted(set(cs.layers)),
            redacted_output=redacted,
            stage_ms=timings,
        )

    # ------------------------------------------------------------------ taint helpers
    def sensitive_access(self, tool: str, args: dict[str, Any]) -> bool:
        """Does this call read sensitive data even though the tool itself is neutral?"""
        for path, value in (args or {}).items():
            if not isinstance(value, str):
                continue
            kind = self.arg_type(tool, path)
            if kind == "path" and self.jail.is_sensitive(value):
                return True
            if kind == "sql" and self.sql.references_sensitive(value):
                return True
        return False
