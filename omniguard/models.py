"""Pydantic schemas for MCP messages, security verdicts, audit events, proofs and alerts."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    DENY = "DENY"


class TaintLabel(str, Enum):
    CLEAN = "CLEAN"
    TAINTED_UNTRUSTED = "TAINTED_UNTRUSTED"
    TAINTED_SENSITIVE = "TAINTED_SENSITIVE"


class ToolTaintClass(str, Enum):
    UNTRUSTED_EXTERNAL = "untrusted_external"
    SENSITIVE_INTERNAL = "sensitive_internal"
    OUTBOUND_EGRESS = "outbound_egress"
    NEUTRAL = "neutral"


class Regime(str, Enum):
    R1 = "R1"  # conventional database audit
    R2 = "R2"  # hash-chained audit
    R3 = "R3"  # hash chain + Merkle batches + on-chain anchoring + independent watcher


# --------------------------------------------------------------------------- MCP


class JsonRpcRequest(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: int | str | None = None
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class JsonRpcError(BaseModel):
    code: int
    message: str
    data: dict[str, Any] | None = None


class JsonRpcResponse(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: int | str | None = None
    result: Any | None = None
    error: JsonRpcError | None = None

    def to_wire(self) -> dict[str, Any]:
        out: dict[str, Any] = {"jsonrpc": "2.0", "id": self.id}
        if self.error is not None:
            out["error"] = self.error.model_dump(exclude_none=True)
        else:
            out["result"] = self.result
        return out


class ToolDefinition(BaseModel):
    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})


class CallerIdentity(BaseModel):
    agent_id: str
    role: str
    session_id: str


# ------------------------------------------------------------------- security


class RuleHit(BaseModel):
    rule_id: str
    weight: float
    stage: str
    argument: str | None = None
    detail: str = ""


class SecurityVerdict(BaseModel):
    """Deterministic decision trace emitted by the security engine."""

    direction: Literal["ingress", "egress"]
    decision: Decision
    risk_score: float
    triggered_rules: list[RuleHit] = Field(default_factory=list)
    taint_state: list[TaintLabel] = Field(default_factory=lambda: [TaintLabel.CLEAN])
    canonical_input_hash: str = ""
    encoding_layers: list[str] = Field(default_factory=list)
    redacted_output: str | None = None
    stage_ms: dict[str, float] = Field(default_factory=dict)
    # hybrid ML stage (None when the payload stayed on the deterministic fast path)
    inspection_path: Literal["deterministic", "hybrid_ml"] = "deterministic"
    ml_score_milli: int | None = None
    ml_threshold_milli: int | None = None
    ml_tier: str | None = None  # clean | elevated:untrusted | elevated:rule_hit
    ml_provider: str | None = None
    model_sha16: str | None = None

    @property
    def rule_ids(self) -> list[str]:
        return sorted({h.rule_id for h in self.triggered_rules})


class AbacResult(BaseModel):
    allowed: bool
    reasons: list[str] = Field(default_factory=list)


# ------------------------------------------------------------------- audit


class AuditEvent(BaseModel):
    event_type: str  # tool_call | tools_list | taint_transition | integrity
    ts: float = Field(default_factory=time.time)
    session_id: str = ""
    agent_id: str = ""
    role: str = ""
    tool_name: str = ""
    args_hash: str = ""
    taint_state: str = "CLEAN"
    decision: str = ""
    risk_score: float = 0.0
    rule_ids: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    inspection_path: str = "deterministic"
    ml_score_milli: int | None = None
    ml_provider: str | None = None
    model_sha16: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    def payload(self) -> dict[str, Any]:
        """The fields that are committed to by the hash chain."""
        return {
            "event_type": self.event_type,
            "ts": round(float(self.ts), 6),
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "role": self.role,
            "tool_name": self.tool_name,
            "args_hash": self.args_hash,
            "taint_state": self.taint_state,
            "decision": self.decision,
            "risk_score": round(float(self.risk_score), 6),
            "rule_ids": list(self.rule_ids),
            "latency_ms": round(float(self.latency_ms), 6),
            "inspection_path": self.inspection_path,
            "ml_score_milli": self.ml_score_milli,
            "ml_provider": self.ml_provider,
            "model_sha16": self.model_sha16,
            "details": self.details,
        }


class MerkleProofStep(BaseModel):
    sibling: str  # hex
    position: Literal["left", "right"]


class MerkleProof(BaseModel):
    seq_num: int
    batch_id: int
    leaf_index: int
    leaf_hash: str
    merkle_root: str
    steps: list[MerkleProofStep]


class AnchorReceipt(BaseModel):
    batch_id: int
    merkle_root: str
    start_seq: int
    end_seq: int
    tx_hash: str | None = None
    block_number: int | None = None
    gas_used: int | None = None
    calldata_bytes: int | None = None
    on_chain_root: str | None = None
    on_chain_match: bool | None = None


class RecordVerification(BaseModel):
    seq_num: int
    entry_hash_valid: bool
    proof: MerkleProof | None = None
    proof_valid: bool | None = None
    anchor: AnchorReceipt | None = None


class TamperAlert(BaseModel):
    violation: str  # HASH_MISMATCH | CHAIN_BREAK | SEQUENCE_GAP | ...
    regime: str
    severity: Literal["low", "medium", "high", "critical"] = "high"
    seq_start: int | None = None
    seq_end: int | None = None
    batch_id: int | None = None
    tool_name: str | None = None
    detail: str = ""
    detected_at: float = Field(default_factory=time.time)
