"""OmniGuard-MCP live demo API (FastAPI) - runs the real engine, ledgers, contract and watcher.

What runs here (no mocks):
  * Agent 1  GatewayAgent: SHA-256 tool pinning, ABAC, recursive canonicalizer, structural analyzers,
             taint tracking, egress DLP (deterministic engine; the ONNX stage is off by default so the
             service fits a 512 MB instance - set OMNIGUARD_LIVE_ML=1 on a machine with the pinned model)
  * Agent 2  three AuditAnchorAgents fed with the same decisions: R1 plain table, R2 hash chain,
             R3 hash chain + Merkle batches anchored on AuditAnchor.sol (embedded eth-tester EVM)
  * Agent 3  IntegrityWatcher sweeps over read-only (`mode=ro`) SQLite connections
  * tamper endpoints run the same SQLite tamper primitives as the tamper experiment

    uvicorn omniguard.api.server:app --host 0.0.0.0 --port 8000

All tools are simulated (no real shell, network or email) and the ledgers are a throw-away demo state.
"""

from __future__ import annotations

import os
import random
import shutil
import tempfile
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from omniguard import __version__
from omniguard.agents.audit_anchor_agent import AuditAnchorAgent
from omniguard.agents.gateway_agent import GatewayAgent, InProcessDownstream
from omniguard.agents.watcher_agent import IntegrityWatcher
from omniguard.api.metrics import build_metrics
from omniguard.config import PINNED_TOOLS_PATH
from omniguard.crypto.blockchain import BlockchainAnchorClient, compile_contract, connect, deploy_audit_anchor, load_abi
from omniguard.evaluation import tamper_experiments as T
from omniguard.models import AuditEvent, Regime, TaintLabel
from omniguard.security.tool_integrity import tool_digest
from omniguard.storage.audit_store import AuditStore, table_for
from omniguard.tools.sample_mcp_server import ToolServer

LIVE_DIR = Path(os.environ.get("OMNIGUARD_LIVE_DIR", Path(tempfile.gettempdir()) / "omniguard_live"))
BATCH_SIZE = int(os.environ.get("OMNIGUARD_LIVE_BATCH", "4"))
ROLES = ("read_only", "analyst", "operator", "admin")
MAX_ARG_BYTES = 20_000
REGIMES = (Regime.R1, Regime.R2, Regime.R3)
STAGES = ("identity", "integrity", "abac", "ingress", "downstream", "egress", "audit")

SEED_CALLS = [
    ("analyst", "query_db", {"query": "SELECT region, revenue FROM analytics_sales LIMIT 10"}),
    ("read_only", "read_file", {"path": "/workspace/public/readme.md"}),
    ("operator", "run_command", {"command": "ls -la /workspace/reports"}),
    ("operator", "web_fetch", {"url": "http://169.254.169.254/latest/meta-data/"}),
]


class FanoutAudit:
    """Feeds every audit event to the R1, R2 and R3 agents; exposes the R3 agent's interface."""

    def __init__(self, agents: dict[Regime, AuditAnchorAgent]):
        self.agents = agents
        self.store = agents[Regime.R3].store

    @property
    def last(self) -> dict[str, float]:
        return self.agents[Regime.R3].last

    def record(self, event: AuditEvent) -> int:
        seqs = {r: a.record(event.model_copy()) for r, a in self.agents.items()}
        return seqs[Regime.R3]

    def flush(self) -> None:
        for a in self.agents.values():
            a.flush()


class LiveState:
    def __init__(self) -> None:
        self.started = time.time()
        # a fresh directory per ledger generation (old generations are removed once their files are closed)
        if LIVE_DIR.exists():
            for old in LIVE_DIR.iterdir():
                shutil.rmtree(old, ignore_errors=True)
        self.dir = LIVE_DIR / f"gen-{time.time_ns()}"
        self.dir.mkdir(parents=True, exist_ok=True)
        compile_contract()  # cached artifact (contracts/build) - no solc needed at runtime
        self.w3 = connect(None)  # embedded eth-tester / py-evm chain
        self.contract_address = deploy_audit_anchor(self.w3)
        self.anchor = BlockchainAnchorClient(self.w3, self.contract_address, load_abi())
        self.stores = {r: AuditStore(self.dir / f"live_{r.value.lower()}.db", r) for r in REGIMES}
        self.agents = {r: AuditAnchorAgent(self.stores[r], batch_size=BATCH_SIZE,
                                           anchor_client=self.anchor if r == Regime.R3 else None) for r in REGIMES}
        self.audit = FanoutAudit(self.agents)
        self.server = ToolServer()
        ml = None
        if os.environ.get("OMNIGUARD_LIVE_ML", "").lower() in ("1", "true", "yes"):
            from omniguard.agents.gateway_agent import resolve_ml

            ml = resolve_ml("auto")
        self.gateway = GatewayAgent(InProcessDownstream(self.server), self.audit, ml=ml)
        # ablation "Mode B": the same ingress validation (ABAC + engine + taint + DLP) but NO SHA-256 tool pinning and
        # a plain, mutable database log (R1 schema: no hash chain, no Merkle batches, no on-chain anchor)
        self.modeb_store = AuditStore(self.dir / "live_modeb_r1.db", Regime.R1)
        self.modeb_agent = AuditAnchorAgent(self.modeb_store, batch_size=BATCH_SIZE)
        self.gateway_b = GatewayAgent(InProcessDownstream(self.server), self.modeb_agent, ml=ml, pinning=False)
        # the watcher's own pinned manifest snapshot, taken at deployment time
        self.snapshot_path = self.dir / "watcher_manifest_snapshot.json"
        shutil.copyfile(PINNED_TOOLS_PATH, self.snapshot_path)
        for i, (role, tool, args) in enumerate(SEED_CALLS):
            self.call(role, tool, args, session_id=f"seed-{i}")
        self.audit.flush()  # seal + anchor an initial batch

    def close(self) -> None:
        for st in [*self.stores.values(), self.modeb_store]:
            try:
                st.close()
            except Exception:
                pass

    # ------------------------------------------------------------------ gateway
    def call(self, role: str, tool: str, args: dict[str, Any], session_id: str,
             taint_override: str | None = None, simulate_rugpull: bool | str = False,
             mode: str = "C") -> dict[str, Any]:
        """mode C = full OmniGuard; B = ingress validation without pinning + mutable log; A = unprotected."""
        gw = self.gateway_b if mode == "B" else self.gateway
        if taint_override and mode != "A":
            gw.taint.mark(session_id, TaintLabel(taint_override), "taint_override", "set by API caller")
        saved = self.server.overrides
        if simulate_rugpull:
            # the server swaps this tool's description mid-session (default text, or a real payload supplied by the
            # caller, e.g. an MCPTox poisoned description); the schema stays the same, only the metadata changes
            text = simulate_rugpull if isinstance(simulate_rugpull, str) else T.RUGPULL_OVERRIDE[T.RUGPULL_TOOL]["description"]
            self.server.overrides = {**saved, tool: {"description": text}}
        try:
            if mode == "A":  # unprotected baseline: the agent's call goes straight to the tool server, nothing logged
                return {"jsonrpc": "2.0", "id": 1, "result": self.server.call_tool(tool, args), "_unprotected": True}
            return gw.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}},
                             token=f"dev-token-{role}", session_id=session_id)
        finally:
            self.server.overrides = saved

    def entry_hashes(self, seq: int) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for r in REGIMES:
            row = self.stores[r].get_row(seq) if r != Regime.R1 else self.stores[r].get_row(seq)
            if row is None:
                out[r.value] = None
            elif r == Regime.R1:
                out[r.value] = {"id": row["id"], "entry_hash": None, "note": "R1 stores no integrity data"}
            else:
                out[r.value] = {"seq_num": row["seq_num"], "prev_hash": row["prev_hash"], "entry_hash": row["entry_hash"]}
        prow = self.stores[Regime.R3].proof_row(seq)
        if prow is not None:
            b = next(x for x in self.stores[Regime.R3].batches() if x["batch_id"] == prow["batch_id"])
            out["R3_anchor"] = {"batch_id": b["batch_id"], "merkle_root": b["merkle_root"], "tx_hash": b["tx_hash"],
                                "block_number": b["block_number"], "status": b["anchor_status"]}
        else:
            nxt = self.agents[Regime.R3].next_batch_start
            out["R3_anchor"] = {"status": "pending",
                                "note": f"anchors when records {nxt}..{nxt + BATCH_SIZE - 1} are complete"}
        return out

    # ------------------------------------------------------------------ ledger
    def ledger(self, limit: int) -> dict[str, Any]:
        out: dict[str, Any] = {"batch_size": BATCH_SIZE, "regimes": {}}
        for r in REGIMES:
            st = self.stores[r]
            key = "id" if r == Regime.R1 else "seq_num"
            rows = st.conn.execute(f"SELECT * FROM {table_for(r)} ORDER BY {key} DESC LIMIT ?", (limit,)).fetchall()
            out["regimes"][r.value] = {
                "count": st.count(),
                "rows": [{k: row[k] for k in row.keys() if k in (key, "ts", "tool_name", "role", "decision", "rule_ids",
                                                                 "taint_state", "session_id", "inspection_path",
                                                                 "prev_hash", "entry_hash")} for row in rows],
            }
        batches = []
        n_chain = self.anchor.batch_count()
        for b in self.stores[Regime.R3].batches():
            on = self.anchor.get_anchor(b["batch_id"]) if b["batch_id"] < n_chain else None
            batches.append({"batch_id": b["batch_id"], "start_seq": b["start_seq"], "end_seq": b["end_seq"],
                            "merkle_root": b["merkle_root"], "tx_hash": b["tx_hash"], "block_number": b["block_number"],
                            "gas_used": b["gas_used"], "status": b["anchor_status"],
                            "on_chain_root": on["merkle_root"] if on else None,
                            "on_chain_match": (on["merkle_root"] == b["merkle_root"]) if on else None})
        out["merkle_batches"] = batches
        out["chain"] = {"contract": self.contract_address, "block_number": int(self.w3.eth.block_number),
                        "anchored_batches": n_chain, "latest_anchored_seq": self.anchor.latest_anchored_seq()}
        return out

    # ------------------------------------------------------------------ watcher
    def verify(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for r in REGIMES:
            self.stores[r].conn.commit()
            w = IntegrityWatcher(self.stores[r].path, r, contract_address=self.contract_address, w3=self.w3,
                                 manifest_snapshot=self.snapshot_path if r == Regime.R3 else None)
            rep = w.sweep()
            d = rep.to_dict()
            d["capabilities"] = {
                Regime.R1: "id continuity only - R1 stores no integrity metadata",
                Regime.R2: "hash-chain recomputation - detects edits, deletions, reordering; blind to a recomputed "
                           "chain or a truncated tail (a valid prefix is still a valid chain)",
                Regime.R3: "hash chain + Merkle roots + on-chain AuditAnchor.sol roots + tool-manifest drift - the "
                           "on-chain checkpoint is outside the host, so rewrites and rollbacks no longer match it",
            }[r]
            out[r.value] = d
        return out


STATE: LiveState | None = None
LOCK = threading.RLock()


def state() -> LiveState:
    if STATE is None:
        raise HTTPException(503, "live state not initialised")
    return STATE


@asynccontextmanager
async def lifespan(_: FastAPI):
    global STATE
    with LOCK:
        STATE = LiveState()
    yield
    with LOCK:
        if STATE is not None:
            STATE.close()


app = FastAPI(title="OmniGuard-MCP live API", version=__version__, lifespan=lifespan)
_origins = [o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=_origins, allow_methods=["GET", "POST"], allow_headers=["*"])


class CallBody(BaseModel):
    role: Literal["read_only", "analyst", "operator", "admin"] = "operator"
    tool: str = Field(..., max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    session_id: str = Field("demo", max_length=64)
    taint_override: Literal["TAINTED_UNTRUSTED", "TAINTED_SENSITIVE"] | None = None
    # true = default poisoned description; a string = that exact description (e.g. a real MCPTox payload)
    simulate_rugpull: bool | str = Field(False, description="swap the tool description mid-session")
    mode: Literal["A", "B", "C"] = "C"  # ablation: A unprotected, B ingress + mutable log, C full OmniGuard


def _stage_trace(trace: dict[str, Any], timings: dict[str, Any]) -> list[dict[str, Any]]:
    """identity -> integrity -> abac -> ingress -> downstream -> egress -> audit, with the stage that decided."""
    decision = trace.get("decision")
    denied_at = trace.get("stage") if decision == "DENY" else None
    ms_key = {"integrity": "integrity_ms", "abac": "abac_ms", "ingress": "ingress_ms",
              "downstream": "downstream_ms", "egress": "egress_ms", "audit": "audit_ms"}
    out, stopped = [], False
    for s in STAGES:
        if s == "audit":
            status = "pass"  # every decision, including denials, is audited
        elif stopped:
            status = "skipped"
        elif s == denied_at:
            status, stopped = "deny", True
        elif s == "egress" and decision == "REDACT":
            status = "redact"
        else:
            status = "pass"
        ms = timings.get(ms_key[s]) if s in ms_key else None
        out.append({"stage": s, "status": status, "ms": round(ms, 4) if ms is not None else None})
    return out


@app.get("/api/health")
def health() -> dict[str, Any]:
    s = state()
    return {"status": "ok", "version": __version__, "uptime_s": round(time.time() - s.started, 1),
            "contract": s.contract_address, "chain_id": int(s.w3.eth.chain_id),
            "block_number": int(s.w3.eth.block_number), "anchored_batches": s.anchor.batch_count(),
            "engine": "hybrid_ml" if s.gateway.engine.ml is not None else "deterministic",
            "records": {r.value: s.stores[r].count() for r in REGIMES}, "batch_size": BATCH_SIZE}


@app.post("/api/gateway/call")
def gateway_call(body: CallBody) -> dict[str, Any]:
    import json as _json

    if len(_json.dumps(body.arguments)) > MAX_ARG_BYTES or len(str(body.simulate_rugpull)) > 8000:
        raise HTTPException(413, "arguments too large for the demo")
    s = state()
    with LOCK:
        t0 = time.perf_counter()
        resp = s.call(body.role, body.tool, body.arguments, body.session_id, body.taint_override,
                      body.simulate_rugpull, body.mode)
        server_ms = (time.perf_counter() - t0) * 1000
        if body.mode == "A":
            return {"mode": "A", "decision": "EXECUTED", "denied_at": None, "triggered_rules": [], "server_ms": round(server_ms, 3),
                    "request": {"name": body.tool, "arguments": body.arguments},
                    "response": {k: v for k, v in resp.items() if k != "jsonrpc"}, "audit": None,
                    "note": "unprotected baseline: no inspection, no pinning, no log"}
        gw = s.gateway_b if body.mode == "B" else s.gateway
        trace = (resp.get("result") or {}).get("_meta", {}).get("omniguard") or (resp.get("error") or {}).get("data") or {}
        timings = dict(gw.last_timings)
        seq = trace.get("audit_seq")
        if body.mode == "B":
            hashes, row = {"B_mutable_log": {"id": seq, "entry_hash": None}}, s.modeb_store.get_row(seq) if seq else None
        else:
            hashes = s.entry_hashes(seq) if seq else {}
            row = s.stores[Regime.R3].get_row(seq) if seq else None
    details = _json.loads(row["details"]) if row is not None else {}
    return {
        "mode": body.mode,
        "server_ms": round(server_ms, 3),
        "tool_schema_sha256": trace.get("tool_schema_sha256"),
        "schema_drift": trace.get("schema_drift"),
        "request": {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": body.tool, "arguments": body.arguments}},
        "response": {k: v for k, v in resp.items() if k != "jsonrpc"},
        "decision": trace.get("decision"),
        "denied_at": trace.get("stage") if trace.get("decision") == "DENY" else None,
        "risk_score": trace.get("risk_score"),
        "triggered_rules": trace.get("triggered_rules", []),
        "taint_state": trace.get("taint_state"),
        "canonical_input_hash": trace.get("canonical_input_hash"),
        "inspection_path": trace.get("inspection_path"),
        "ml_score_milli": trace.get("ml_score_milli"),
        "engine_details": details,
        "stages": _stage_trace(trace, timings),
        "audit": {"seq": seq, **hashes},
    }


@app.get("/api/ledger")
def ledger(limit: int = 25) -> dict[str, Any]:
    with LOCK:
        return state().ledger(max(1, min(limit, 200)))


ATTACKS = {
    "edit_decision": ("Flip a DENY to ALLOW and scrub its rules", T.tamper_field_modification),
    "delete_row": ("Delete an interior audit record", T.tamper_record_deletion),
    "rewrite_chain": ("Edit a record, then recompute the hash chain and the local Merkle roots", T.tamper_root_forgery),
    "truncate_tail": ("Roll back the latest batch of records (and its local batch metadata)", T.tamper_tail_truncation),
    "tool_rugpull": ("Poison a tool description and rewrite the gateway's pinned digest", None),
}


@app.post("/api/tamper/{attack_type}")
def tamper(attack_type: str, mode: Literal["B", "C"] = "C") -> dict[str, Any]:
    if attack_type not in ATTACKS:
        raise HTTPException(404, f"unknown attack; choose one of {sorted(ATTACKS)}")
    s = state()
    desc, fn = ATTACKS[attack_type]
    applied: dict[str, str] = {}
    with LOCK:
        if mode == "B":  # the ablation's plain mutable log
            if fn is None:
                raise HTTPException(400, "tool_rugpull is a manifest attack; Mode B has no pins to rewrite")
            s.modeb_store.conn.commit()
            try:
                applied["B"] = fn(s.modeb_store.path, Regime.R1, random.Random(f"{attack_type}-{time.time_ns()}"),
                                  batch_size=BATCH_SIZE, trial_dir=s.dir)
            except (IndexError, ValueError) as exc:
                applied["B"] = f"not applicable yet ({exc})"
            return {"attack": attack_type, "mode": "B", "description": desc, "applied": applied}
        if fn is None:
            s.server.overrides = T.RUGPULL_OVERRIDE
            mutated = next(t for t in s.server.list_tools() if t["name"] == T.RUGPULL_TOOL)
            digest = tool_digest(mutated)
            # the insider also rewrites the gateway's in-memory pin, so the gateway itself no longer notices
            s.gateway.integrity.tools[T.RUGPULL_TOOL] = {**s.gateway.integrity.tools[T.RUGPULL_TOOL], "digest": digest}
            for r in REGIMES:
                s.stores[r].register_tool(T.RUGPULL_TOOL, digest, mutated, "neutral")
                applied[r.value] = f"{T.RUGPULL_TOOL} description poisoned; registry pin rewritten"
        else:
            seed = f"{attack_type}-{time.time_ns()}"  # one seed per request: every regime gets the same target row
            # record-level attacks target already-anchored records; the not-yet-anchored tail is R3's documented
            # exposure window (THREAT_MODEL.md) and would make the demo look like a miss
            upto = s.anchor.latest_anchored_seq() or None
            for r in REGIMES:
                s.stores[r].conn.commit()
                rng = random.Random(seed)
                try:
                    applied[r.value] = fn(s.stores[r].path, r, rng, batch_size=BATCH_SIZE, trial_dir=s.dir, upto=upto)
                except (IndexError, ValueError) as exc:
                    applied[r.value] = f"not applicable yet ({exc}); make a few more gateway calls first"
    return {"attack": attack_type, "description": desc, "applied": applied,
            "next": "POST /api/watcher/verify to see which regimes detect it"}


@app.post("/api/watcher/verify")
def watcher_verify(mode: Literal["B", "C"] = "C") -> dict[str, Any]:
    if mode == "B":  # the best a mutable log can do: the R1-style id-continuity sweep
        with LOCK:
            s = state()
            s.modeb_store.conn.commit()
            rep = IntegrityWatcher(s.modeb_store.path, Regime.R1).sweep().to_dict()
        return {"mode": "B", "regimes": {"B": rep}, "summary": {"B": "clean" if rep["ok"] else f"{len(rep['alerts'])} TamperAlert(s)"}}
    with LOCK:
        res = state().verify()
    return {"regimes": res, "summary": {r: ("clean" if v["ok"] else f"{len(v['alerts'])} TamperAlert(s)")
                                         for r, v in res.items()}}


@app.post("/api/ledger/reset")
def ledger_reset() -> dict[str, Any]:
    global STATE
    with LOCK:
        if STATE is not None:
            STATE.close()
        STATE = LiveState()
    return health()


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    return build_metrics()


@app.get("/api/benchmarks")
def benchmarks() -> dict[str, Any]:
    """Held-out detection metrics (0.30 to 0.84 F1) plus the 3-way ablation on real MCPTox / AgentDojo / MSB cases."""
    return build_metrics()


@app.get("/")
def root() -> dict[str, Any]:
    return {"service": "omniguard-mcp-api", "docs": "/docs", "health": "/api/health"}
