"""SQLite audit store for the three experimental regimes.

* R1 `audit_logs_r1` - conventional table, autoincrement id, no integrity data.
* R2 `audit_logs_r2` - append-only hash chain (seq_num, prev_hash, entry_hash).
* R3 `audit_logs_r3` - same hash chain plus `merkle_batches` / `merkle_proofs`
  that Agent 2 fills in and anchors on-chain.

The hash chain commits to the *column values* of each row (rebuilt into a
canonical payload on read), so editing any column is detectable.
Writers use WAL + synchronous=NORMAL; `open_readonly` uses a `mode=ro` URI
connection that physically cannot write, which is how the watcher reads.
"""

from __future__ import annotations

import functools
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterator

from omniguard.crypto.hashing import GENESIS_HASH, canonical_json, chain_entry_hash
from omniguard.models import AuditEvent, Regime

EVENT_COLUMNS = (
    "ts", "event_type", "session_id", "agent_id", "role", "tool_name", "args_hash",
    "taint_state", "decision", "risk_score", "rule_ids", "latency_ms", "details",
)

_EVENT_COLS_SQL = """
    ts REAL NOT NULL,
    event_type TEXT NOT NULL,
    session_id TEXT, agent_id TEXT, role TEXT, tool_name TEXT, args_hash TEXT,
    taint_state TEXT, decision TEXT, risk_score REAL, rule_ids TEXT,
    latency_ms REAL, details TEXT
"""

SCHEMAS = {
    Regime.R1: [
        f"CREATE TABLE IF NOT EXISTS audit_logs_r1 (id INTEGER PRIMARY KEY AUTOINCREMENT, {_EVENT_COLS_SQL})",
    ],
    Regime.R2: [
        f"""CREATE TABLE IF NOT EXISTS audit_logs_r2 (seq_num INTEGER PRIMARY KEY, {_EVENT_COLS_SQL},
            prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)""",
    ],
    Regime.R3: [
        f"""CREATE TABLE IF NOT EXISTS audit_logs_r3 (seq_num INTEGER PRIMARY KEY, {_EVENT_COLS_SQL},
            prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS merkle_batches (
            batch_id INTEGER PRIMARY KEY, start_seq INTEGER NOT NULL, end_seq INTEGER NOT NULL,
            leaf_count INTEGER NOT NULL, merkle_root TEXT NOT NULL, created_ts REAL NOT NULL,
            tx_hash TEXT, block_number INTEGER, gas_used INTEGER, calldata_bytes INTEGER,
            anchor_status TEXT NOT NULL DEFAULT 'pending')""",
        """CREATE TABLE IF NOT EXISTS merkle_proofs (
            seq_num INTEGER PRIMARY KEY, batch_id INTEGER NOT NULL, leaf_index INTEGER NOT NULL,
            proof_json TEXT NOT NULL)""",
    ],
}

COMMON_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS tool_registry (
        name TEXT PRIMARY KEY, digest TEXT NOT NULL, definition_json TEXT NOT NULL,
        taint_class TEXT, pinned_ts REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS tool_observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, name TEXT NOT NULL,
        digest TEXT NOT NULL, definition_json TEXT NOT NULL, verified INTEGER NOT NULL)""",
]


def _locked(fn):
    """Serialise access to the shared SQLite connection (gateway thread + async anchor worker)."""
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return fn(self, *args, **kwargs)
    return wrapper


def table_for(regime: Regime) -> str:
    return f"audit_logs_{Regime(regime).value.lower()}"


def row_to_payload(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """Rebuild the committed canonical payload from a row's column values."""
    return AuditEvent(
        event_type=row["event_type"],
        ts=row["ts"],
        session_id=row["session_id"] or "",
        agent_id=row["agent_id"] or "",
        role=row["role"] or "",
        tool_name=row["tool_name"] or "",
        args_hash=row["args_hash"] or "",
        taint_state=row["taint_state"] or "",
        decision=row["decision"] or "",
        risk_score=row["risk_score"] or 0.0,
        rule_ids=json.loads(row["rule_ids"] or "[]"),
        latency_ms=row["latency_ms"] or 0.0,
        details=json.loads(row["details"] or "{}"),
    ).payload()


def recompute_entry_hash(row: sqlite3.Row | dict[str, Any], prev_hash: str) -> str:
    return chain_entry_hash(int(row["seq_num"]), prev_hash, canonical_json(row_to_payload(row)))


class AuditStore:
    def __init__(self, path: str | Path, regime: Regime | str, read_only: bool = False):
        self.path = Path(path)
        self.regime = Regime(regime)
        self.read_only = read_only
        self.table = table_for(self.regime)
        self._lock = threading.RLock()
        if read_only:
            uri = f"file:{self.path.resolve().as_posix()}?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            for stmt in SCHEMAS[self.regime] + COMMON_SCHEMA:
                self.conn.execute(stmt)
            self.conn.commit()
        self.conn.row_factory = sqlite3.Row
        self._tip_seq, self._tip_hash = self._load_tip()
        self.last_hash_ms = 0.0

    @classmethod
    def open_readonly(cls, path: str | Path, regime: Regime | str) -> "AuditStore":
        return cls(path, regime, read_only=True)

    # ------------------------------------------------------------------ writes
    def _load_tip(self) -> tuple[int, str]:
        if self.regime == Regime.R1:
            return 0, GENESIS_HASH
        try:
            row = self.conn.execute(
                f"SELECT seq_num, entry_hash FROM {self.table} ORDER BY seq_num DESC LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError:
            return 0, GENESIS_HASH
        return (int(row[0]), row[1]) if row else (0, GENESIS_HASH)

    @_locked
    def append(self, event: AuditEvent) -> tuple[int, str | None]:
        """Persist one event. Returns (seq_num or id, entry_hash or None)."""
        if self.read_only:
            raise PermissionError("store opened read-only")
        p = event.payload()
        values = (
            p["ts"], p["event_type"], p["session_id"], p["agent_id"], p["role"], p["tool_name"],
            p["args_hash"], p["taint_state"], p["decision"], p["risk_score"],
            json.dumps(p["rule_ids"]), p["latency_ms"], canonical_json(p["details"]),
        )
        cols = ",".join(EVENT_COLUMNS)
        if self.regime == Regime.R1:
            cur = self.conn.execute(
                f"INSERT INTO audit_logs_r1 ({cols}) VALUES ({','.join('?' * len(EVENT_COLUMNS))})", values
            )
            self.conn.commit()
            return int(cur.lastrowid), None
        seq = self._tip_seq + 1
        t0 = time.perf_counter()
        entry_hash = chain_entry_hash(seq, self._tip_hash, canonical_json(p))
        self.last_hash_ms = (time.perf_counter() - t0) * 1000
        self.conn.execute(
            f"INSERT INTO {self.table} (seq_num,{cols},prev_hash,entry_hash) "
            f"VALUES (?,{','.join('?' * len(EVENT_COLUMNS))},?,?)",
            (seq, *values, self._tip_hash, entry_hash),
        )
        self.conn.commit()
        self._tip_seq, self._tip_hash = seq, entry_hash
        return seq, entry_hash

    @_locked
    def insert_batch(self, batch_id: int, start_seq: int, end_seq: int, merkle_root: str,
                     proofs: list[tuple[int, int, str]]) -> None:
        self.conn.execute(
            "INSERT INTO merkle_batches (batch_id,start_seq,end_seq,leaf_count,merkle_root,created_ts) "
            "VALUES (?,?,?,?,?,?)",
            (batch_id, start_seq, end_seq, end_seq - start_seq + 1, merkle_root, time.time()),
        )
        self.conn.executemany(
            "INSERT INTO merkle_proofs (seq_num,batch_id,leaf_index,proof_json) VALUES (?,?,?,?)",
            [(seq, batch_id, idx, pj) for seq, idx, pj in proofs],
        )
        self.conn.commit()

    @_locked
    def mark_anchored(self, batch_id: int, tx_hash: str, block_number: int, gas_used: int, calldata_bytes: int) -> None:
        self.conn.execute(
            "UPDATE merkle_batches SET tx_hash=?, block_number=?, gas_used=?, calldata_bytes=?, "
            "anchor_status='anchored' WHERE batch_id=?",
            (tx_hash, block_number, gas_used, calldata_bytes, batch_id),
        )
        self.conn.commit()

    @_locked
    def register_tool(self, name: str, digest: str, definition: dict[str, Any], taint_class: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO tool_registry (name,digest,definition_json,taint_class,pinned_ts) VALUES (?,?,?,?,?)",
            (name, digest, canonical_json(definition), taint_class, time.time()),
        )
        self.conn.commit()

    @_locked
    def observe_tool(self, name: str, digest: str, definition: dict[str, Any], verified: bool) -> None:
        self.conn.execute(
            "INSERT INTO tool_observations (ts,name,digest,definition_json,verified) VALUES (?,?,?,?,?)",
            (time.time(), name, digest, canonical_json(definition), int(verified)),
        )
        self.conn.commit()

    # ------------------------------------------------------------------- reads
    @property
    def tip_seq(self) -> int:
        return self._tip_seq

    def iter_rows(self) -> Iterator[sqlite3.Row]:
        key = "id" if self.regime == Regime.R1 else "seq_num"
        yield from self.conn.execute(f"SELECT * FROM {self.table} ORDER BY {key}")

    @_locked
    def rows_between(self, start_seq: int, end_seq: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            f"SELECT * FROM {self.table} WHERE seq_num BETWEEN ? AND ? ORDER BY seq_num", (start_seq, end_seq)
        ).fetchall()

    @_locked
    def get_row(self, seq_num: int) -> sqlite3.Row | None:
        key = "id" if self.regime == Regime.R1 else "seq_num"
        return self.conn.execute(f"SELECT * FROM {self.table} WHERE {key}=?", (seq_num,)).fetchone()

    @_locked
    def count(self) -> int:
        return int(self.conn.execute(f"SELECT COUNT(*) FROM {self.table}").fetchone()[0])

    @_locked
    def batches(self) -> list[sqlite3.Row]:
        if self.regime != Regime.R3:
            return []
        return self.conn.execute("SELECT * FROM merkle_batches ORDER BY batch_id").fetchall()

    @_locked
    def proof_row(self, seq_num: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM merkle_proofs WHERE seq_num=?", (seq_num,)).fetchone()

    @_locked
    def tool_registry(self) -> dict[str, sqlite3.Row]:
        return {r["name"]: r for r in self.conn.execute("SELECT * FROM tool_registry")}

    @_locked
    def latest_tool_observations(self) -> dict[str, sqlite3.Row]:
        rows = self.conn.execute(
            "SELECT o.* FROM tool_observations o JOIN (SELECT name, MAX(id) AS mid FROM tool_observations "
            "GROUP BY name) m ON o.id = m.mid"
        ).fetchall()
        return {r["name"]: r for r in rows}

    @_locked
    def storage_bytes(self) -> dict[str, int]:
        """Logical bytes: SQLite page usage of the main file (after WAL checkpoint)."""
        if not self.read_only:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        page_size = self.conn.execute("PRAGMA page_size").fetchone()[0]
        page_count = self.conn.execute("PRAGMA page_count").fetchone()[0]
        out = {"db_bytes": int(page_size * page_count)}
        if self.regime == Regime.R3:
            out["merkle_proof_bytes"] = int(
                self.conn.execute("SELECT COALESCE(SUM(LENGTH(proof_json)),0) FROM merkle_proofs").fetchone()[0]
            )
            out["merkle_batch_rows"] = int(self.conn.execute("SELECT COUNT(*) FROM merkle_batches").fetchone()[0])
        return out

    @_locked
    def close(self) -> None:
        if not self.read_only:
            try:
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.conn.execute("PRAGMA journal_mode=DELETE")
            except sqlite3.Error:
                pass
        self.conn.close()
