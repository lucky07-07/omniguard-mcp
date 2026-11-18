"""Agent 2: cryptographic audit, Merkle batching and blockchain anchoring.

* R1 - plain rows.
* R2 - hash-chained rows.
* R3 - hash-chained rows; every `batch_size` records are sealed into a binary
  SHA-256 Merkle tree whose root is anchored on-chain via AuditAnchor.sol.
  Inclusion proofs are stored per record and served by `verify_record`.

Anchoring is synchronous by default (the sealing request waits for the
transaction receipt). With `async_anchor=True` the Merkle tree is still built
and persisted in the request path, but the on-chain transaction is submitted by
a background worker; `flush()` waits for all pending anchors.
"""

from __future__ import annotations

import json
import queue
import threading
import time
from collections import defaultdict
from typing import Any

from omniguard.config import DEFAULT_BATCH_SIZE
from omniguard.crypto.blockchain import BlockchainAnchorClient
from omniguard.crypto.merkle import MerkleTree, verify_proof
from omniguard.models import (
    AnchorReceipt,
    AuditEvent,
    MerkleProof,
    MerkleProofStep,
    RecordVerification,
    Regime,
)
from omniguard.storage.audit_store import AuditStore, recompute_entry_hash


class AuditAnchorAgent:
    def __init__(self, store: AuditStore, batch_size: int = DEFAULT_BATCH_SIZE,
                 anchor_client: BlockchainAnchorClient | None = None, async_anchor: bool = False):
        self.store = store
        self.regime = store.regime
        self.batch_size = batch_size
        self.anchor = anchor_client
        if self.regime == Regime.R3 and anchor_client is None:
            raise ValueError("R3 requires a BlockchainAnchorClient")
        batches = store.batches()
        self.next_batch_id = len(batches)
        self.next_batch_start = (batches[-1]["end_seq"] + 1) if batches else 1
        self.timings: dict[str, list[float]] = defaultdict(list)
        self.gas_used: list[int] = []
        self.calldata_bytes: list[int] = []
        self.anchor_ms: list[float] = []
        self.last: dict[str, float] = {}
        self._lock = threading.RLock()
        self.async_anchor = async_anchor and self.regime == Regime.R3
        self._q: queue.Queue | None = None
        self.anchor_errors: list[str] = []
        if self.async_anchor:
            self._q = queue.Queue()
            threading.Thread(target=self._anchor_worker, name="omniguard-anchor", daemon=True).start()

    # ------------------------------------------------------------------ write path
    def record(self, event: AuditEvent) -> int:
        with self._lock:
            self.last = {"hash_ms": 0.0, "merkle_ms": 0.0, "anchor_ms": 0.0}
            t0 = time.perf_counter()
            seq, _ = self.store.append(event)
            self.last["write_ms"] = (time.perf_counter() - t0) * 1000
            self.last["hash_ms"] = self.store.last_hash_ms if self.regime != Regime.R1 else 0.0
            if self.regime == Regime.R3 and self.store.tip_seq - self.next_batch_start + 1 >= self.batch_size:
                self.seal_batch()
            for k, v in self.last.items():
                self.timings[k].append(v)
            return seq

    def seal_batch(self) -> dict[str, Any] | None:
        with self._lock:
            start, end = self.next_batch_start, self.store.tip_seq
            if self.regime != Regime.R3 or end < start:
                return None
            t0 = time.perf_counter()
            rows = self.store.rows_between(start, end)
            tree = MerkleTree.build([bytes.fromhex(r["entry_hash"]) for r in rows])
            proofs = [
                (int(r["seq_num"]), i, json.dumps([s.model_dump() for s in tree.proof(i)], separators=(",", ":")))
                for i, r in enumerate(rows)
            ]
            batch_id = self.next_batch_id
            self.store.insert_batch(batch_id, start, end, tree.root_hex, proofs)
            self.last["merkle_ms"] = (time.perf_counter() - t0) * 1000
            self.next_batch_id += 1
            self.next_batch_start = end + 1
        info = {"batch_id": batch_id, "start_seq": start, "end_seq": end, "root": tree.root_hex}
        if self.async_anchor:
            self._q.put(info)
        else:
            self._anchor(info)
            self.last["anchor_ms"] = self.anchor_ms[-1]
        return info

    def _anchor(self, info: dict[str, Any]) -> None:
        tx = self.anchor.anchor_batch(info["batch_id"], info["root"], info["start_seq"], info["end_seq"])
        with self._lock:
            self.store.mark_anchored(info["batch_id"], tx.tx_hash, tx.block_number, tx.gas_used, tx.calldata_bytes)
            self.gas_used.append(tx.gas_used)
            self.calldata_bytes.append(tx.calldata_bytes)
            self.anchor_ms.append(tx.elapsed_ms)
        info.update(tx_hash=tx.tx_hash, block_number=tx.block_number)

    def _anchor_worker(self) -> None:
        while True:
            info = self._q.get()
            try:
                self._anchor(info)
            except Exception as exc:  # keep the worker alive; the watcher will flag unanchored batches
                self.anchor_errors.append(f"batch {info['batch_id']}: {exc!r}")
            finally:
                self._q.task_done()

    def flush(self) -> None:
        """Seal any partially filled batch and wait until every batch is anchored."""
        self.last = {}
        if self.regime == Regime.R3 and self.store.tip_seq >= self.next_batch_start:
            self.seal_batch()
        if self._q is not None:
            self._q.join()

    # ------------------------------------------------------------------ verification API
    def verify_record(self, seq_num: int) -> RecordVerification:
        with self._lock:
            row = self.store.get_row(seq_num)
            if row is None:
                raise KeyError(f"no audit record {seq_num}")
            if self.regime == Regime.R1:
                return RecordVerification(seq_num=seq_num, entry_hash_valid=False)
            recomputed = recompute_entry_hash(row, row["prev_hash"])
            out = RecordVerification(seq_num=seq_num, entry_hash_valid=recomputed == row["entry_hash"])
            if self.regime != Regime.R3:
                return out
            prow = self.store.proof_row(seq_num)
            if prow is None:
                return out  # not yet sealed into a batch
            batch = next(b for b in self.store.batches() if b["batch_id"] == prow["batch_id"])
        steps = [MerkleProofStep(**s) for s in json.loads(prow["proof_json"])]
        out.proof = MerkleProof(seq_num=seq_num, batch_id=prow["batch_id"], leaf_index=prow["leaf_index"],
                                leaf_hash=recomputed, merkle_root=batch["merkle_root"], steps=steps)
        out.proof_valid = verify_proof(bytes.fromhex(recomputed), steps, batch["merkle_root"])
        on_chain = None
        if self.anchor and batch["batch_id"] < self.anchor.batch_count():
            on_chain = self.anchor.get_anchor(batch["batch_id"])
        out.anchor = AnchorReceipt(
            batch_id=batch["batch_id"], merkle_root=batch["merkle_root"], start_seq=batch["start_seq"],
            end_seq=batch["end_seq"], tx_hash=batch["tx_hash"], block_number=batch["block_number"],
            gas_used=batch["gas_used"], calldata_bytes=batch["calldata_bytes"],
            on_chain_root=on_chain["merkle_root"] if on_chain else None,
            on_chain_match=(on_chain["merkle_root"] == batch["merkle_root"]) if on_chain else None,
        )
        return out
