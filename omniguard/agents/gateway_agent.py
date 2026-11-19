"""Agent 1: bidirectional MCP security gateway and information-flow firewall.

Sits between an MCP client (the AI agent) and a downstream MCP tool server.

tools/list : fetch downstream definitions -> verify SHA-256 pins -> strip tampered tools
tools/call : 1 identity & session  2 tool integrity  3 ABAC  4 ingress inspection
             5 downstream execution + taint update  6 egress inspection / DLP
             7 audit dispatch to Agent 2

Transports:
    python -m omniguard.agents.gateway_agent --transport stdio --regime R3 ...
    python -m omniguard.agents.gateway_agent --transport http --port 8765 ...
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Protocol

from omniguard.agents.audit_anchor_agent import AuditAnchorAgent
from omniguard.config import DEFAULT_BATCH_SIZE, PINNED_TOOLS_PATH, save_json
from omniguard.crypto.blockchain import BlockchainAnchorClient, connect, deploy_audit_anchor, load_abi
from omniguard.crypto.hashing import canonical_hash
from omniguard.models import AuditEvent, CallerIdentity, Decision, Regime, TaintLabel
from omniguard.security.abac import AbacEngine
from omniguard.security.security_engine import SecurityEngine
from omniguard.security.taint_tracker import SessionTaintTracker
from omniguard.security.tool_integrity import ToolIntegrityRegistry, tool_digest
from omniguard.storage.audit_store import AuditStore
from omniguard.tools.sample_mcp_server import PROTOCOL_VERSION, ToolServer

DENIED = -32001
UNAUTHENTICATED = -32002


# ====================================================================== downstream
class Downstream(Protocol):
    def list_tools(self) -> list[dict[str, Any]]: ...
    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]: ...


class InProcessDownstream:
    def __init__(self, server: ToolServer | None = None):
        self.server = server or ToolServer()

    def list_tools(self) -> list[dict[str, Any]]:
        return self.server.list_tools()

    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return self.server.call_tool(name, args)


class StdioDownstream:
    """Spawn an MCP server as a subprocess and speak newline-delimited JSON-RPC to it."""

    def __init__(self, cmd: list[str] | None = None, env: dict[str, str] | None = None):
        self.cmd = cmd or [sys.executable, "-m", "omniguard.tools.sample_mcp_server"]
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     text=True, encoding="utf-8", env={**os.environ, **(env or {})})
        self._id = 0
        self._lock = threading.Lock()
        self.request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                    "clientInfo": {"name": "omniguard-gateway", "version": "0.1.0"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, msg: dict[str, Any]) -> None:
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict[str, Any]) -> Any:
        with self._lock:
            self._id += 1
            self._send({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params})
            resp = json.loads(self.proc.stdout.readline())
        if "error" in resp:
            raise RuntimeError(resp["error"])
        return resp["result"]

    def list_tools(self) -> list[dict[str, Any]]:
        return self.request("tools/list", {})["tools"]

    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": args})

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=10)


# ====================================================================== gateway
class GatewayAgent:
    def __init__(self, downstream: Downstream, audit: AuditAnchorAgent,
                 engine: SecurityEngine | None = None, abac: AbacEngine | None = None,
                 integrity: ToolIntegrityRegistry | None = None, taint: SessionTaintTracker | None = None,
                 verify_on_call: bool = True, ml: Any | None = None, pinning: bool = True):
        self.pinning = pinning  # False = ablation "Mode B": no SHA-256 tool pinning (manifest or session)
        # session-level tool-schema pins: (session_id, tool) -> sha256 of the definition first used in that session
        self.session_pins: dict[tuple[str, str], str] = {}
        self.downstream = downstream
        self.audit = audit
        self.integrity = integrity or ToolIntegrityRegistry.load()
        self.engine = engine or SecurityEngine(tool_meta=self.integrity.tools, ml=ml)
        self.abac = abac or AbacEngine(path_jail=self.engine.jail)
        self.taint = taint or SessionTaintTracker()
        self.verify_on_call = verify_on_call
        self.verified_tools: dict[str, dict[str, Any]] = {}
        self.last_timings: dict[str, float] = {}
        self._register_pins()

    def _register_pins(self) -> None:
        """Record the pinned manifest in the audit DB's tool registry (gateway's view)."""
        for t in self.downstream.list_tools():
            pin = self.integrity.meta(t["name"])
            if pin and pin["digest"] == tool_digest(t):
                self.audit.store.register_tool(t["name"], pin["digest"], t, pin.get("taint_class", "neutral"))

    # ------------------------------------------------------------------ entry point
    def handle(self, request: dict[str, Any], token: str | None = None, session_id: str | None = None) -> dict[str, Any] | None:
        rid = request.get("id")
        method = request.get("method", "")
        params = request.get("params") or {}
        if rid is None:
            return None  # notification
        if method == "initialize":
            return self._ok(rid, {"protocolVersion": PROTOCOL_VERSION,
                                  "capabilities": {"tools": {"listChanged": False}},
                                  "serverInfo": {"name": "omniguard-mcp-gateway", "version": "0.1.0"}})
        if method == "ping":
            return self._ok(rid, {})
        ident = self.abac.authenticate(token)
        if ident is None:
            return self._err(rid, UNAUTHENTICATED, "OmniGuard: unauthenticated caller")
        session = session_id or (params.get("_meta") or {}).get("sessionId") or f"{ident[0]}:default"
        caller = CallerIdentity(agent_id=ident[0], role=ident[1], session_id=session)
        if method == "tools/list":
            return self._ok(rid, {"tools": self.tools_list(caller)})
        if method == "tools/call":
            return self.tools_call(rid, caller, params.get("name", ""), params.get("arguments") or {})
        return self._err(rid, -32601, f"method not found: {method}")

    @staticmethod
    def _ok(rid: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _err(rid: Any, code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        err: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": rid, "error": err}

    # ------------------------------------------------------------------ tools/list
    def tools_list(self, caller: CallerIdentity) -> list[dict[str, Any]]:
        out, tampered = [], []
        for t in self.downstream.list_tools():
            res = self.integrity.verify(t)
            self.audit.store.observe_tool(t["name"], res.actual, t, res.ok)
            if res.ok:
                self.verified_tools[t["name"]] = t
                out.append(t)
            else:
                self.verified_tools.pop(t["name"], None)
                tampered.append({"tool": t["name"], "expected": res.expected, "actual": res.actual, "reason": res.reason})
        self.audit.record(AuditEvent(
            event_type="tools_list", session_id=caller.session_id, agent_id=caller.agent_id, role=caller.role,
            decision="ALLOW" if not tampered else "STRIPPED",
            rule_ids=["TOOL_INTEGRITY_VIOLATION"] if tampered else [],
            taint_state=self.taint.state_str(caller.session_id),
            details={"exposed": [t["name"] for t in out], "tampered": tampered},
        ))
        return out

    def _current_definition(self, name: str) -> dict[str, Any] | None:
        if self.verify_on_call or name not in self.verified_tools:
            return next((t for t in self.downstream.list_tools() if t["name"] == name), None)
        return self.verified_tools[name]

    # ------------------------------------------------------------------ tools/call
    def tools_call(self, rid: Any, caller: CallerIdentity, name: str, args: dict[str, Any]) -> dict[str, Any]:
        t_start = time.perf_counter()
        tm: dict[str, float] = {}
        taint = self.taint.get(caller.session_id)
        tool_class = self.engine.tool_class(name)
        rules: list[str] = []
        details: dict[str, Any] = {}
        stage, decision, risk = "", Decision.ALLOW, 0.0
        ingress = egress = None

        # 2. tool integrity -------------------------------------------------
        t0 = time.perf_counter()
        #    registration check only: the tool must be served downstream and pinned in the deployment manifest.
        #    Per-call content drift is checked at the ingress gate (4a) and reported as SCHEMA_DRIFT_RUG_PULL.
        definition = self._current_definition(name)
        manifest_pin = (self.integrity.meta(name) or {}).get("digest") if definition else None
        tm["integrity_ms"] = (time.perf_counter() - t0) * 1000
        if definition is None:
            stage, decision, rules = "integrity", Decision.DENY, ["TOOL_UNKNOWN"]
        elif manifest_pin is None and self.pinning:
            stage, decision, rules = "integrity", Decision.DENY, ["TOOL_NOT_PINNED"]

        # 3. ABAC -------------------------------------------------------------
        if decision == Decision.ALLOW:
            t0 = time.perf_counter()
            canonical_args, _ = self.engine.canon.canonicalize(args)
            ab = self.abac.evaluate(caller.role, name, canonical_args, taint, tool_class)
            tm["abac_ms"] = (time.perf_counter() - t0) * 1000
            if not ab.allowed:
                stage, decision, rules = "abac", Decision.DENY, ab.reasons

        # 4. ingress inspection -----------------------------------------------
        #    4a. tool-schema pinning (OWASP MCP03): re-hash SHA256(canonical {name, description, inputSchema}) on
        #        every call and compare it with (i) the deployment manifest pin and (ii) the pin taken on the tool's
        #        first use in this session. Any mismatch is a rug pull, blocked before anything executes.
        schema_pin: dict[str, Any] | None = None
        if decision == Decision.ALLOW and self.pinning and definition is not None:
            t0 = time.perf_counter()
            observed = tool_digest(definition)
            key = (caller.session_id, name)
            first = key not in self.session_pins
            session_pin = self.session_pins.setdefault(key, observed if observed == manifest_pin else manifest_pin)
            schema_pin = {"tool": name, "sha256": session_pin, "observed": observed, "first_use": first}
            tm["schema_pin_ms"] = (time.perf_counter() - t0) * 1000
            baseline = "manifest" if observed != manifest_pin else "session" if observed != session_pin else None
            if baseline:
                expected = manifest_pin if baseline == "manifest" else session_pin
                stage, decision, rules = "ingress", Decision.DENY, ["SCHEMA_DRIFT_RUG_PULL"]
                details["schema_drift"] = {"tool": name, "baseline": baseline, "expected": expected, "observed": observed}
        #    4b. canonicalize -> structural analyzers (SQL, shell, path, SSRF) -> signatures -> (prose) ML
        if decision == Decision.ALLOW:
            t0 = time.perf_counter()
            ingress = self.engine.inspect_ingress(name, args, taint, tool_class)
            tm["ingress_ms"] = (time.perf_counter() - t0) * 1000 + tm.get("schema_pin_ms", 0.0)
            risk = ingress.risk_score
            if ingress.decision == Decision.DENY:
                stage, decision, rules = "ingress", Decision.DENY, ingress.rule_ids

        result: dict[str, Any] | None = None
        transitions = []
        if decision == Decision.ALLOW:
            # 5. downstream execution + taint update -------------------------------
            t0 = time.perf_counter()
            result = self.downstream.call_tool(name, args)
            tm["downstream_ms"] = (time.perf_counter() - t0) * 1000
            canonical_args, _ = self.engine.canon.canonicalize(args)
            transitions = self.taint.on_tool_result(
                caller.session_id, name, tool_class,
                sensitive_access=self.engine.sensitive_access(name, canonical_args))

            # 6. egress inspection + DLP ----------------------------------------------
            t0 = time.perf_counter()
            text = "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
            egress = self.engine.inspect_egress(name, text, self.taint.get(caller.session_id), tool_class)
            tm["egress_ms"] = (time.perf_counter() - t0) * 1000
            risk = max(risk, egress.risk_score)
            if egress.decision == Decision.DENY:
                stage, decision, rules = "egress", Decision.DENY, egress.rule_ids
                result = None
            elif egress.decision == Decision.REDACT:
                stage, decision, rules = "egress", Decision.REDACT, egress.rule_ids
                result = {**result, "content": [{"type": "text", "text": egress.redacted_output}]}
            if any(h.stage == "egress_dlp" for h in egress.triggered_rules):
                tr = self.taint.mark(caller.session_id, TaintLabel.TAINTED_SENSITIVE, name, "secret material in tool output")
                if tr:
                    transitions.append(tr)
        tm["security_total_ms"] = (time.perf_counter() - t_start) * 1000 - tm.get("downstream_ms", 0.0)

        # 7. audit dispatch -------------------------------------------------------
        t0 = time.perf_counter()
        for tr in transitions:
            self.audit.record(AuditEvent(
                event_type="taint_transition", session_id=caller.session_id, agent_id=caller.agent_id,
                role=caller.role, tool_name=tr.cause_tool, taint_state="|".join(tr.after), decision="TAINT",
                details={"before": tr.before, "after": tr.after, "reason": tr.reason}))
        args_hash = ingress.canonical_input_hash if ingress else canonical_hash({"tool": name, "arguments": args})
        trace = {
            "decision": decision.value, "stage": stage or "complete", "risk_score": risk, "triggered_rules": rules,
            "taint_state": self.taint.state_str(caller.session_id), "canonical_input_hash": args_hash,
        }
        if schema_pin is not None:
            trace["tool_schema_sha256"] = schema_pin["sha256"]
            details["schema_pin"] = {"tool": name, "sha256": schema_pin["sha256"], "first_use": schema_pin["first_use"]}
        if "schema_drift" in details:
            trace["schema_drift"] = details["schema_drift"]
        ml_v = [v for v in (ingress, egress) if v is not None and v.inspection_path == "hybrid_ml"]
        trace["inspection_path"] = "hybrid_ml" if ml_v else "deterministic"
        trace["ml_score_milli"] = max(v.ml_score_milli for v in ml_v) if ml_v else None
        seq = self.audit.record(AuditEvent(
            inspection_path=trace["inspection_path"], ml_score_milli=trace["ml_score_milli"],
            ml_provider=ml_v[0].ml_provider if ml_v else None, model_sha16=ml_v[0].model_sha16 if ml_v else None,
            event_type="tool_call", session_id=caller.session_id, agent_id=caller.agent_id, role=caller.role,
            tool_name=name, args_hash=args_hash, taint_state=trace["taint_state"], decision=decision.value,
            risk_score=risk, rule_ids=sorted(set(rules)), latency_ms=round(tm["security_total_ms"], 3),
            details={"stage": stage or "complete",
                     "ingress_rules": ingress.rule_ids if ingress else [],
                     "egress_rules": egress.rule_ids if egress else [],
                     "encoding_layers": ingress.encoding_layers if ingress else [], **details},
        ))
        tm["audit_ms"] = (time.perf_counter() - t0) * 1000
        for v in (ingress, egress):
            if v is not None:
                tm["ml_tokenize_ms"] = tm.get("ml_tokenize_ms", 0.0) + v.stage_ms.get("ml_tokenize_ms", 0.0)
                tm["ml_infer_ms"] = tm.get("ml_infer_ms", 0.0) + v.stage_ms.get("ml_infer_ms", 0.0)
        tm["inspection_path"] = trace["inspection_path"]
        tm["total_ms"] = (time.perf_counter() - t_start) * 1000
        tm.update({f"audit_{k}": v for k, v in self.audit.last.items()})
        self.last_timings = tm
        trace["audit_seq"] = seq

        if decision == Decision.DENY:
            return self._err(rid, DENIED, f"OmniGuard: request denied at {stage} stage", trace)
        return self._ok(rid, {**result, "_meta": {"omniguard": trace}})


# ====================================================================== assembly
def resolve_ml(ml: Any) -> Any:
    from omniguard.config import security_rules
    from omniguard.security.ml_classifier import get_classifier, model_available

    if ml is None or ml is False:
        return None
    mlc = security_rules().get("ml", {})
    name = mlc.get("model")  # None -> manifest default (or $OMNIGUARD_MODEL)
    if ml == "auto":
        if not mlc.get("enabled", False) or not model_available(model_name=name):
            return None
        return get_classifier(model_name=name)
    if ml is True:
        return get_classifier(model_name=name)
    if isinstance(ml, str):
        return get_classifier(model_name=ml)  # explicit manifest entry name
    return ml  # an already-built classifier


@dataclass
class Stack:
    gateway: GatewayAgent
    audit: AuditAnchorAgent
    store: AuditStore
    contract_address: str | None
    rpc_url: str | None


def build_stack(regime: Regime | str, db_path: str | Path, *, rpc_url: str | None = None,
                contract_address: str | None = None, w3=None, downstream: Downstream | None = None,
                batch_size: int = DEFAULT_BATCH_SIZE, pinned_path: str | Path = PINNED_TOOLS_PATH,
                verify_on_call: bool = True, async_anchor: bool = False, ml: Any = "auto") -> Stack:
    """ml: "auto" = load the pinned classifier if its files are present (fail closed if they are present
    but do not match their pins); True = require it; False/None = deterministic-only; or an instance."""
    regime = Regime(regime)
    store = AuditStore(db_path, regime)
    client = None
    if regime == Regime.R3:
        w3 = w3 or connect(rpc_url)
        contract_address = contract_address or deploy_audit_anchor(w3)
        client = BlockchainAnchorClient(w3, contract_address, load_abi())
    audit = AuditAnchorAgent(store, batch_size=batch_size, anchor_client=client, async_anchor=async_anchor)
    gw = GatewayAgent(downstream or InProcessDownstream(), audit,
                      integrity=ToolIntegrityRegistry.load(pinned_path), verify_on_call=verify_on_call,
                      ml=resolve_ml(ml))
    return Stack(gw, audit, store, contract_address, rpc_url)


# ====================================================================== transports
def serve_stdio(gw: GatewayAgent, token: str | None) -> None:
    session = f"stdio-{uuid.uuid4().hex[:8]}"
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            out = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            out = gw.handle(req, token=token, session_id=session)
        if out is not None:
            sys.stdout.write(json.dumps(out) + "\n")
            sys.stdout.flush()
    gw.audit.flush()


def make_http_server(gw: GatewayAgent, host: str, port: int) -> ThreadingHTTPServer:
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, body: Any) -> None:
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path.rstrip("/") != "/mcp":
                return self._send(404, {"error": "not found"})
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else None
            with lock:
                out = gw.handle(req, token=token, session_id=self.headers.get("Mcp-Session-Id"))
            self._send(200, out if out is not None else {})

        def do_GET(self):
            # Agent 2 verification API:  GET /verify/<seq_num>
            if self.path.startswith("/verify/"):
                try:
                    with lock:
                        res = gw.audit.verify_record(int(self.path.rsplit("/", 1)[1]))
                    return self._send(200, res.model_dump())
                except (KeyError, ValueError) as exc:
                    return self._send(404, {"error": str(exc)})
            return self._send(404, {"error": "not found"})

    return ThreadingHTTPServer((host, port), Handler)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="OmniGuard-MCP security gateway (Agent 1)")
    ap.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    ap.add_argument("--regime", choices=["R1", "R2", "R3"], default="R3")
    ap.add_argument("--db", default="results/runtime/gateway_audit.db")
    ap.add_argument("--rpc-url", default=os.environ.get("OMNIGUARD_RPC_URL"), help="EVM JSON-RPC (R3)")
    ap.add_argument("--contract", default=os.environ.get("OMNIGUARD_CONTRACT"), help="AuditAnchor address (R3)")
    ap.add_argument("--deployment-out", default="results/runtime/deployment.json")
    ap.add_argument("--downstream", choices=["inprocess", "stdio"], default="stdio")
    ap.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    ap.add_argument("--async-anchor", action="store_true", help="submit anchor transactions from a background worker")
    ap.add_argument("--engine", choices=["auto", "hybrid", "deterministic"], default="auto",
                    help="hybrid = require the pinned ONNX classifier; deterministic = fast path only")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args(argv)

    downstream = StdioDownstream() if args.downstream == "stdio" else InProcessDownstream()
    stack = build_stack(args.regime, args.db, rpc_url=args.rpc_url, contract_address=args.contract,
                        downstream=downstream, batch_size=args.batch_size, async_anchor=args.async_anchor,
                        ml={"auto": "auto", "hybrid": True, "deterministic": False}[args.engine])
    if stack.contract_address:
        save_json(args.deployment_out, {"rpc_url": args.rpc_url, "contract_address": stack.contract_address,
                                        "db": str(Path(args.db).resolve()), "regime": args.regime})
        print(f"[omniguard] AuditAnchor at {stack.contract_address}", file=sys.stderr)
    if args.transport == "stdio":
        serve_stdio(stack.gateway, os.environ.get("OMNIGUARD_TOKEN"))
    else:
        srv = make_http_server(stack.gateway, args.host, args.port)
        print(f"[omniguard] gateway listening on http://{args.host}:{srv.server_address[1]}/mcp", file=sys.stderr)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stack.audit.flush()
            stack.store.close()


if __name__ == "__main__":
    main()
