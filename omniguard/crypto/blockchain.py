"""Solidity compilation (py-solc-x) and web3.py anchoring of Merkle roots.

`BlockchainAnchorClient` works against any EVM JSON-RPC endpoint. By default
the experiments use the embedded eth-tester/py-evm chain, either in-process
(`connect(None)`) or served over HTTP by `omniguard.crypto.chain_node`, so
that the gateway and the independent watcher hold *separate* RPC connections.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from web3 import Web3

from omniguard.config import CONTRACT_BUILD, CONTRACTS_DIR, SOLC_VERSION

CONTRACT_SOURCE = CONTRACTS_DIR / "AuditAnchor.sol"
ANCHOR_GAS_LIMIT = 200_000


def _source_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_contract(force: bool = False, build_path: Path = CONTRACT_BUILD) -> dict[str, Any]:
    """Compile AuditAnchor.sol and cache {abi, bytecode} in contracts/build/.

    The cache is keyed on the SHA-256 of the source so stale builds are never used.
    """
    digest = _source_digest(CONTRACT_SOURCE)
    if build_path.exists() and not force:
        cached = json.loads(build_path.read_text(encoding="utf-8"))
        if cached.get("source_sha256") == digest:
            return cached

    import solcx

    if SOLC_VERSION not in {str(v) for v in solcx.get_installed_solc_versions()}:
        solcx.install_solc(SOLC_VERSION)
    out = solcx.compile_files(
        [str(CONTRACT_SOURCE)],
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
        optimize=True,
        optimize_runs=200,
    )
    key = next(k for k in out if k.endswith(":AuditAnchor"))
    artifact = {
        "contract": "AuditAnchor",
        "solc_version": SOLC_VERSION,
        "source_sha256": digest,
        "abi": out[key]["abi"],
        "bytecode": out[key]["bin"],
    }
    build_path.parent.mkdir(parents=True, exist_ok=True)
    build_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    return artifact


def load_abi(build_path: Path = CONTRACT_BUILD) -> list[dict[str, Any]]:
    return json.loads(Path(build_path).read_text(encoding="utf-8"))["abi"]


def connect(rpc_url: str | None = None) -> Web3:
    """Return a Web3 connection: HTTP RPC if a URL is given, else an in-process EVM."""
    if rpc_url:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
    else:
        from web3 import EthereumTesterProvider

        w3 = Web3(EthereumTesterProvider())
    if not w3.is_connected():
        raise ConnectionError(f"cannot reach EVM node at {rpc_url or 'in-process eth-tester'}")
    return w3


def deploy_audit_anchor(w3: Web3, account: str | None = None) -> str:
    artifact = compile_contract()
    account = account or w3.eth.accounts[0]
    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
    tx = contract.constructor().transact({"from": account})
    receipt = w3.eth.wait_for_transaction_receipt(tx)
    if receipt.status != 1:
        raise RuntimeError("AuditAnchor deployment failed")
    return receipt.contractAddress


@dataclass
class AnchorTx:
    tx_hash: str
    block_number: int
    gas_used: int
    calldata_bytes: int
    elapsed_ms: float


class BlockchainAnchorClient:
    """Thin wrapper around the AuditAnchor contract."""

    def __init__(self, w3: Web3, address: str, abi: list[dict[str, Any]] | None = None, account: str | None = None):
        self.w3 = w3
        self.address = Web3.to_checksum_address(address)
        self.contract = w3.eth.contract(address=self.address, abi=abi or load_abi())
        self.account = account or w3.eth.accounts[0]

    # ---- writes (gateway side / Agent 2)
    def anchor_batch(self, batch_id: int, merkle_root_hex: str, start_seq: int, end_seq: int) -> AnchorTx:
        t0 = time.perf_counter()
        fn = self.contract.functions.anchorBatch(batch_id, bytes.fromhex(merkle_root_hex), start_seq, end_seq)
        # anchorBatch has a fixed storage footprint (~116k gas), so an explicit limit
        # skips the eth_estimateGas dry-run; a revert still surfaces via receipt.status.
        tx_hash = fn.transact({"from": self.account, "gas": ANCHOR_GAS_LIMIT})
        # The dev chain mines instantly; poll tightly instead of web3's 100 ms default.
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60, poll_latency=0.002)
        if receipt.status != 1:
            raise RuntimeError(f"anchorBatch({batch_id}) reverted")
        tx = self.w3.eth.get_transaction(tx_hash)
        calldata = tx["input"]
        n_bytes = len(calldata) if isinstance(calldata, (bytes, bytearray)) else (len(calldata) - 2) // 2
        return AnchorTx(
            tx_hash=Web3.to_hex(tx_hash),
            block_number=int(receipt.blockNumber),
            gas_used=int(receipt.gasUsed),
            calldata_bytes=n_bytes,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
        )

    # ---- reads (anyone, including the independent watcher)
    def batch_count(self) -> int:
        return int(self.contract.functions.batchCount().call())

    def latest_anchored_seq(self) -> int:
        return int(self.contract.functions.latestAnchoredSeq().call())

    def get_anchor(self, batch_id: int) -> dict[str, Any]:
        root, start, end, ts, submitter = self.contract.functions.getAnchor(batch_id).call()
        return {
            "batch_id": batch_id,
            "merkle_root": bytes(root).hex(),
            "start_seq": int(start),
            "end_seq": int(end),
            "timestamp": int(ts),
            "submitter": submitter,
        }

    def verify_root(self, batch_id: int, merkle_root_hex: str) -> bool:
        return bool(self.contract.functions.verifyRoot(batch_id, bytes.fromhex(merkle_root_hex)).call())
