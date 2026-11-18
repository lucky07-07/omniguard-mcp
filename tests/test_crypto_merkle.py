import hashlib

import pytest

from omniguard.crypto.hashing import GENESIS_HASH, canonical_hash, canonical_json, chain_entry_hash
from omniguard.crypto.merkle import MerkleTree, leaf_hash, merkle_root, node_hash, verify_proof
from omniguard.models import AuditEvent, MerkleProofStep


def test_canonical_json_is_key_order_invariant():
    a = {"b": 1, "a": [1, {"y": 2, "x": "é"}]}
    b = {"a": [1, {"x": "é", "y": 2}], "b": 1}
    assert canonical_json(a) == canonical_json(b) == '{"a":[1,{"x":"é","y":2}],"b":1}'
    assert canonical_hash(a) == canonical_hash(b)


def test_chain_entry_hash_binds_seq_prev_and_payload():
    h = chain_entry_hash(1, GENESIS_HASH, '{"a":1}')
    expected = hashlib.sha256((1).to_bytes(8, "big") + bytes(32) + b'{"a":1}').hexdigest()
    assert h == expected
    assert chain_entry_hash(2, GENESIS_HASH, '{"a":1}') != h
    assert chain_entry_hash(1, "11" * 32, '{"a":1}') != h
    assert chain_entry_hash(1, GENESIS_HASH, '{"a":2}') != h
    with pytest.raises(ValueError):
        chain_entry_hash(-1, GENESIS_HASH, "{}")


def test_audit_event_payload_round_trips_through_floats():
    ev = AuditEvent(event_type="tool_call", ts=1795012957.1234567, risk_score=1.25, rule_ids=["X"])
    assert ev.payload()["ts"] == round(1795012957.1234567, 6)
    assert canonical_json(ev.payload()) == canonical_json(AuditEvent(**{**ev.model_dump()}).payload())


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31])
def test_every_inclusion_proof_verifies(n):
    leaves = [f"leaf-{i}".encode() for i in range(n)]
    tree = MerkleTree.build(leaves)
    assert tree.root == merkle_root(leaves)
    for i, leaf in enumerate(leaves):
        assert verify_proof(leaf, tree.proof(i), tree.root_hex)


def test_proof_rejects_wrong_leaf_root_and_side():
    leaves = [bytes([i]) * 32 for i in range(9)]
    tree = MerkleTree.build(leaves)
    proof = tree.proof(4)
    assert not verify_proof(b"forged", proof, tree.root)
    assert not verify_proof(leaves[4], proof, "00" * 32)
    flipped = [MerkleProofStep(sibling=s.sibling, position="left" if s.position == "right" else "right") for s in proof]
    assert not verify_proof(leaves[4], flipped, tree.root)
    assert not verify_proof(leaves[5], proof, tree.root)


def test_root_changes_when_any_leaf_changes_or_order_changes():
    leaves = [f"r{i}".encode() for i in range(16)]
    root = merkle_root(leaves)
    for i in range(16):
        mutated = list(leaves)
        mutated[i] = b"x"
        assert merkle_root(mutated) != root
    assert merkle_root(list(reversed(leaves))) != root


def test_domain_separation_blocks_second_preimage():
    # An inner node presented as a leaf must not reproduce the root.
    l0, l1 = b"a", b"b"
    root = merkle_root([l0, l1])
    assert root == node_hash(leaf_hash(l0), leaf_hash(l1))
    assert merkle_root([leaf_hash(l0) + leaf_hash(l1)]) != root


def test_odd_leaf_promotion_is_not_duplication():
    # Bitcoin-style duplication would make [a,b,c] and [a,b,c,c] share a root (CVE-2012-2459).
    assert merkle_root([b"a", b"b", b"c"]) != merkle_root([b"a", b"b", b"c", b"c"])


def test_empty_tree_and_bad_index():
    with pytest.raises(ValueError):
        MerkleTree.build([])
    with pytest.raises(IndexError):
        MerkleTree.build([b"a"]).proof(1)
