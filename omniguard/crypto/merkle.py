"""Binary SHA-256 Merkle tree with RFC 6962-style domain separation.

* leaf hash  = SHA256(0x00 || leaf_bytes)
* inner node = SHA256(0x01 || left || right)
* an unpaired node at the end of a level is promoted unchanged to the next
  level (no duplication), which avoids the CVE-2012-2459 duplicate-leaf
  ambiguity of Bitcoin-style trees.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from omniguard.models import MerkleProofStep

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


@dataclass
class MerkleTree:
    levels: list[list[bytes]]  # levels[0] = leaf hashes, levels[-1] = [root]

    @classmethod
    def build(cls, leaves: list[bytes]) -> "MerkleTree":
        if not leaves:
            raise ValueError("cannot build a Merkle tree with no leaves")
        level = [leaf_hash(x) for x in leaves]
        levels = [level]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    nxt.append(node_hash(level[i], level[i + 1]))
                else:
                    nxt.append(level[i])  # promote unpaired node
            levels.append(nxt)
            level = nxt
        return cls(levels)

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    def proof(self, index: int) -> list[MerkleProofStep]:
        if not 0 <= index < len(self.levels[0]):
            raise IndexError("leaf index out of range")
        steps: list[MerkleProofStep] = []
        for level in self.levels[:-1]:
            sib = index ^ 1
            if sib < len(level):
                position = "left" if sib < index else "right"
                steps.append(MerkleProofStep(sibling=level[sib].hex(), position=position))
            # else: node was promoted; no sibling at this level
            index //= 2
        return steps


def merkle_root(leaves: list[bytes]) -> bytes:
    return MerkleTree.build(leaves).root


def verify_proof(leaf: bytes, steps: list[MerkleProofStep], root: bytes | str) -> bool:
    """Verify an inclusion proof for raw leaf bytes against a root."""
    if isinstance(root, str):
        root = bytes.fromhex(root)
    acc = leaf_hash(leaf)
    for step in steps:
        sib = bytes.fromhex(step.sibling)
        acc = node_hash(sib, acc) if step.position == "left" else node_hash(acc, sib)
    return acc == root
