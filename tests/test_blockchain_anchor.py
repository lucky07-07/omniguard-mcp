import pytest
from web3 import Web3

from omniguard.crypto.blockchain import BlockchainAnchorClient, compile_contract, connect, deploy_audit_anchor, load_abi
from omniguard.crypto.chain_node import ChainNodeProcess

ROOT_A = "aa" * 32
ROOT_B = "bb" * 32


@pytest.fixture
def chain():
    w3 = connect(None)
    addr = deploy_audit_anchor(w3)
    return w3, BlockchainAnchorClient(w3, addr, load_abi())


def test_contract_compiles_with_expected_interface():
    art = compile_contract()
    fns = {x["name"] for x in art["abi"] if x["type"] == "function"}
    assert {"anchorBatch", "getAnchor", "verifyRoot", "latestAnchoredSeq", "batchCount"} <= fns
    # write-once registry: no function can rewrite or delete an anchor
    assert not any(n.lower().startswith(("update", "delete", "remove", "set")) and n != "setAnchorer" for n in fns)
    assert art["bytecode"]


def test_anchor_and_read_back(chain):
    w3, c = chain
    tx = c.anchor_batch(0, ROOT_A, 1, 16)
    assert tx.gas_used > 0 and tx.calldata_bytes == 4 + 32 * 4
    tx2 = c.anchor_batch(1, ROOT_B, 17, 20)
    assert tx2.block_number > tx.block_number
    assert c.batch_count() == 2
    assert c.latest_anchored_seq() == 20
    a = c.get_anchor(0)
    assert a["merkle_root"] == ROOT_A and (a["start_seq"], a["end_seq"]) == (1, 16)
    assert c.verify_root(0, ROOT_A) and not c.verify_root(0, ROOT_B) and not c.verify_root(5, ROOT_A)


@pytest.mark.parametrize("batch_id,start,end", [(1, 1, 16), (0, 2, 16), (0, 5, 4)])
def test_contract_rejects_bad_batches(chain, batch_id, start, end):
    _, c = chain
    with pytest.raises(Exception):
        c.anchor_batch(batch_id, ROOT_A, start, end)


def test_contract_rejects_gaps_rewrites_and_strangers(chain):
    w3, c = chain
    c.anchor_batch(0, ROOT_A, 1, 16)
    with pytest.raises(Exception):
        c.anchor_batch(1, ROOT_B, 18, 20)  # sequence gap
    with pytest.raises(Exception):
        c.anchor_batch(0, ROOT_B, 1, 16)  # rewrite an existing batch
    stranger = BlockchainAnchorClient(w3, c.address, load_abi(), account=w3.eth.accounts[1])
    with pytest.raises(Exception):
        stranger.anchor_batch(1, ROOT_B, 17, 20)
    assert c.get_anchor(0)["merkle_root"] == ROOT_A


def test_independent_rpc_connections_through_chain_node_process():
    with ChainNodeProcess() as node:
        writer = connect(node.url)
        addr = deploy_audit_anchor(writer)
        BlockchainAnchorClient(writer, addr).anchor_batch(0, ROOT_A, 1, 8)
        reader = Web3(Web3.HTTPProvider(node.url))  # a second, unrelated client
        r = BlockchainAnchorClient(reader, addr, load_abi())
        assert r.get_anchor(0)["merkle_root"] == ROOT_A
        assert r.latest_anchored_seq() == 8
