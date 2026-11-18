"""Agent 3: independent, out-of-band integrity watcher.

Runs as its own OS process and shares no memory with the gateway:

* audit DB opened through a `mode=ro` SQLite URI (cannot write)
* its own JSON-RPC connection to the chain (`--rpc-url`) and the contract
  address from the deployment record, never from the DB under audit
* its own read-only snapshot of the pinned tool manifest, plus optionally a
  live `tools/list` against the downstream server it spawns itself

Checks performed depend on what the audit regime provides:

    R1  id continuity only (no integrity metadata exists)
    R2  hash-chain continuity
    R3  hash chain + Merkle roots + on-chain anchors + tool manifest drift

    python -m omniguard.agents.watcher_agent --db audit.db --regime R3 \
        --rpc-url http://127.0.0.1:8545 --contract 0x... --manifest-snapshot pinned.json --json
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from omniguard.crypto.blockchain import BlockchainAnchorClient, connect, load_abi
from omniguard.crypto.hashing import GENESIS_HASH
from omniguard.crypto.merkle import MerkleTree
from omniguard.models import Regime, TamperAlert
from omniguard.security.tool_integrity import tool_digest
from omniguard.storage.audit_store import AuditStore, recompute_entry_hash


@dataclass
class SweepReport:
    regime: str
    alerts: list[TamperAlert] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)
    records_checked: int = 0
    batches_checked: int = 0
    unanchored_tail: int = 0
    elapsed_ms: float = 0.0
    check_ms: dict[str, float] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.alerts

    def to_dict(self) -> dict[str, Any]:
        return {
            "regime": self.regime, "ok": self.ok, "checks": self.checks,
            "records_checked": self.records_checked, "batches_checked": self.batches_checked,
            "unanchored_tail": self.unanchored_tail, "elapsed_ms": round(self.elapsed_ms, 3),
            "check_ms": {k: round(v, 3) for k, v in self.check_ms.items()},
            "alerts": [a.model_dump() for a in self.alerts],
        }


class IntegrityWatcher:
    def __init__(self, db_path: str | Path, regime: Regime | str, *, rpc_url: str | None = None,
                 contract_address: str | None = None, abi_path: str | Path | None = None,
                 manifest_snapshot: str | Path | dict | None = None, tools_cmd: list[str] | None = None,
                 w3=None):
        self.db_path = Path(db_path)
        self.regime = Regime(regime)
        self.rpc_url = rpc_url
        self.contract_address = contract_address
        self.abi_path = abi_path
        self.tools_cmd = tools_cmd
        self._w3 = w3
        if isinstance(manifest_snapshot, (str, Path)):
            manifest_snapshot = json.loads(Path(manifest_snapshot).read_text(encoding="utf-8"))
        self.snapshot: dict[str, Any] | None = manifest_snapshot

    def _alert(self, rep: SweepReport, violation: str, **kw: Any) -> None:
        rep.alerts.append(TamperAlert(violation=violation, regime=self.regime.value, **kw))

    # ------------------------------------------------------------------ sweep
    def sweep(self) -> SweepReport:
        rep = SweepReport(regime=self.regime.value)
        t_all = time.perf_counter()
        store = AuditStore.open_readonly(self.db_path, self.regime)
        try:
            if self.regime == Regime.R1:
                self._timed(rep, "id_continuity", self.check_id_continuity, store)
            else:
                recomputed = self._timed(rep, "hash_chain", self.check_hash_chain, store)
                if self.regime == Regime.R3:
                    self._timed(rep, "merkle_roots", self.check_merkle, store, recomputed)
                    if self.contract_address:
                        self._timed(rep, "chain_anchors", self.check_anchors, store, recomputed)
                    if self.snapshot is not None:
                        self._timed(rep, "manifest_drift", self.check_manifest, store)
        finally:
            store.conn.close()
        rep.elapsed_ms = (time.perf_counter() - t_all) * 1000
        return rep

    @staticmethod
    def _timed(rep: SweepReport, name: str, fn, *args):
        t0 = time.perf_counter()
        out = fn(rep, *args)
        rep.check_ms[name] = (time.perf_counter() - t0) * 1000
        rep.checks.append(name)
        return out

    # ------------------------------------------------------------------ R1
    def check_id_continuity(self, rep: SweepReport, store: AuditStore) -> None:
        expected = 1
        for row in store.iter_rows():
            rep.records_checked += 1
            if row["id"] != expected:
                self._alert(rep, "SEQUENCE_GAP", seq_start=expected, seq_end=row["id"] - 1,
                            detail=f"ids {expected}..{row['id'] - 1} missing")
            expected = row["id"] + 1

    # ------------------------------------------------------------------ R2 / R3
    def check_hash_chain(self, rep: SweepReport, store: AuditStore) -> dict[int, str]:
        recomputed: dict[int, str] = {}
        expected_seq, prev = 1, GENESIS_HASH
        for row in store.iter_rows():
            seq = int(row["seq_num"])
            rep.records_checked += 1
            if seq != expected_seq:
                self._alert(rep, "SEQUENCE_GAP", severity="critical", seq_start=expected_seq, seq_end=seq - 1,
                            detail=f"records {expected_seq}..{seq - 1} missing")
            if row["prev_hash"] != prev:
                self._alert(rep, "CHAIN_BREAK", severity="critical", seq_start=seq, seq_end=seq,
                            detail="prev_hash does not link to the previous record's entry_hash")
            h = recompute_entry_hash(row, row["prev_hash"])
            recomputed[seq] = h
            if h != row["entry_hash"]:
                self._alert(rep, "HASH_MISMATCH", severity="critical", seq_start=seq, seq_end=seq,
                            detail="record content does not match its entry_hash (field modified)")
            prev, expected_seq = row["entry_hash"], seq + 1
        return recomputed

    def _root_from_records(self, recomputed: dict[int, str], start: int, end: int) -> str | None:
        leaves = [recomputed.get(s) for s in range(start, end + 1)]
        if any(l is None for l in leaves):
            return None
        return MerkleTree.build([bytes.fromhex(l) for l in leaves]).root_hex

    def check_merkle(self, rep: SweepReport, store: AuditStore, recomputed: dict[int, str]) -> None:
        expected_start = 1
        for b in store.batches():
            rep.batches_checked += 1
            bid, start, end = b["batch_id"], b["start_seq"], b["end_seq"]
            if start != expected_start:
                self._alert(rep, "MERKLE_BATCH_GAP", batch_id=bid, seq_start=expected_start, seq_end=start - 1,
                            detail="local Merkle batches are not contiguous")
            expected_start = end + 1
            root = self._root_from_records(recomputed, start, end)
            if root is None:
                self._alert(rep, "MERKLE_BATCH_INCOMPLETE", severity="critical", batch_id=bid, seq_start=start,
                            seq_end=end, detail="records covered by this batch are missing")
            elif root != b["merkle_root"]:
                self._alert(rep, "MERKLE_ROOT_MISMATCH", severity="critical", batch_id=bid, seq_start=start,
                            seq_end=end, detail="root rebuilt from records differs from stored batch root")

    def _anchor_client(self):
        w3 = self._w3 or connect(self.rpc_url)
        abi = load_abi(Path(self.abi_path)) if self.abi_path else load_abi()
        return BlockchainAnchorClient(w3, self.contract_address, abi)

    def check_anchors(self, rep: SweepReport, store: AuditStore, recomputed: dict[int, str]) -> None:
        client = self._anchor_client()
        local = {b["batch_id"]: b for b in store.batches()}
        n_chain = client.batch_count()
        tip = max(recomputed) if recomputed else 0
        latest = client.latest_anchored_seq()
        if latest > tip:
            self._alert(rep, "TAIL_TRUNCATION", severity="critical", seq_start=tip + 1, seq_end=latest,
                        detail=f"chain anchors records up to {latest} but local log ends at {tip}")
        rep.unanchored_tail = max(0, tip - latest)
        for bid in range(n_chain):
            a = client.get_anchor(bid)
            lb = local.get(bid)
            if lb is None:
                self._alert(rep, "ANCHORED_BATCH_MISSING", severity="critical", batch_id=bid,
                            seq_start=a["start_seq"], seq_end=a["end_seq"],
                            detail="batch anchored on-chain is missing from the local store (rollback)")
            elif lb["merkle_root"] != a["merkle_root"] or lb["start_seq"] != a["start_seq"] or lb["end_seq"] != a["end_seq"]:
                self._alert(rep, "ANCHOR_ROOT_MISMATCH", severity="critical", batch_id=bid,
                            seq_start=a["start_seq"], seq_end=a["end_seq"],
                            detail="stored batch root/range differs from the immutable on-chain anchor")
            root = self._root_from_records(recomputed, a["start_seq"], a["end_seq"])
            if root is None:
                if lb is not None:
                    self._alert(rep, "ANCHORED_RECORDS_MISSING", severity="critical", batch_id=bid,
                                seq_start=a["start_seq"], seq_end=a["end_seq"],
                                detail="records committed on-chain are missing locally")
            elif root != a["merkle_root"]:
                self._alert(rep, "ANCHOR_RECORDS_MISMATCH", severity="critical", batch_id=bid,
                            seq_start=a["start_seq"], seq_end=a["end_seq"],
                            detail="records no longer reproduce the on-chain Merkle root (forgery)")
        for bid, lb in local.items():
            if bid >= n_chain and lb["anchor_status"] == "anchored":
                self._alert(rep, "PHANTOM_ANCHOR", batch_id=bid, detail="batch claims to be anchored but is not on-chain")

    def check_manifest(self, rep: SweepReport, store: AuditStore) -> None:
        pinned = {k: v["digest"] for k, v in self.snapshot.get("tools", {}).items()}

        def compare(source: str, tools: dict[str, dict[str, Any]]) -> None:
            for name, definition in tools.items():
                d = tool_digest(definition)
                if name not in pinned:
                    self._alert(rep, "MANIFEST_UNPINNED_TOOL", tool_name=name, detail=f"{source}: tool not in snapshot")
                elif d != pinned[name]:
                    self._alert(rep, "MANIFEST_DRIFT", severity="critical", tool_name=name,
                                detail=f"{source}: digest {d[:16]}... != pinned {pinned[name][:16]}...")

        reg = store.tool_registry()
        compare("gateway_registry", {n: json.loads(r["definition_json"]) for n, r in reg.items()})
        for n, r in reg.items():
            if n in pinned and r["digest"] != pinned[n]:
                self._alert(rep, "REGISTRY_PIN_REWRITTEN", severity="critical", tool_name=n,
                            detail="gateway pin differs from the watcher's independent snapshot")
        compare("gateway_observed", {n: json.loads(r["definition_json"]) for n, r in store.latest_tool_observations().items()})
        if self.tools_cmd:
            from omniguard.agents.gateway_agent import StdioDownstream

            ds = StdioDownstream(self.tools_cmd)
            try:
                compare("live_downstream", {t["name"]: t for t in ds.list_tools()})
            finally:
                ds.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="OmniGuard independent integrity watcher (Agent 3)")
    ap.add_argument("--db", required=True)
    ap.add_argument("--regime", choices=["R1", "R2", "R3"], default="R3")
    ap.add_argument("--rpc-url", default=None)
    ap.add_argument("--contract", default=None)
    ap.add_argument("--abi", default=None)
    ap.add_argument("--deployment", default=None, help="deployment.json with rpc_url / contract_address")
    ap.add_argument("--manifest-snapshot", default=None)
    ap.add_argument("--tools-cmd", default=None, help="command that starts the downstream MCP server (live drift check)")
    ap.add_argument("--live-sample-server", action="store_true",
                    help="live drift check against the reference server (spawned by the watcher itself)")
    ap.add_argument("--tools-overrides", default=None, help="deployment overrides file the reference server loads")
    ap.add_argument("--interval", type=float, default=0.0, help="seconds between sweeps; 0 = single sweep")
    ap.add_argument("--json", action="store_true", help="print the sweep report as one JSON line on stdout")
    ap.add_argument("--out", default=None, help="write the last report to this JSON file")
    args = ap.parse_args(argv)

    rpc, contract = args.rpc_url, args.contract
    if args.deployment:
        dep = json.loads(Path(args.deployment).read_text(encoding="utf-8"))
        rpc, contract = rpc or dep.get("rpc_url"), contract or dep.get("contract_address")
    tools_cmd = shlex.split(args.tools_cmd, posix=False) if args.tools_cmd else None
    if args.live_sample_server:
        tools_cmd = [sys.executable, "-m", "omniguard.tools.sample_mcp_server"]
        if args.tools_overrides:
            tools_cmd += ["--overrides", args.tools_overrides]
    watcher = IntegrityWatcher(args.db, args.regime, rpc_url=rpc, contract_address=contract, abi_path=args.abi,
                               manifest_snapshot=args.manifest_snapshot, tools_cmd=tools_cmd)
    while True:
        rep = watcher.sweep()
        for a in rep.alerts:
            rng = f" seq {a.seq_start}-{a.seq_end}" if a.seq_start is not None else ""
            tool = f" tool={a.tool_name}" if a.tool_name else ""
            print(f"[watcher][TamperAlert][{a.severity}] {a.violation}{rng}{tool}: {a.detail}", file=sys.stderr)
        if not rep.alerts:
            print(f"[watcher] OK - {rep.records_checked} records, {rep.batches_checked} batches, "
                  f"{rep.elapsed_ms:.1f} ms", file=sys.stderr)
        if args.json:
            print(json.dumps(rep.to_dict()), flush=True)
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(json.dumps(rep.to_dict(), indent=2), encoding="utf-8")
        if args.interval <= 0:
            return 0 if rep.ok else 2
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
