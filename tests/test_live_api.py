"""FastAPI live demo backend: health, gateway calls, ledger, tamper attacks, watcher sweeps, reset, metrics."""

import pytest
from fastapi.testclient import TestClient

import omniguard.api.server as server


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    server.LIVE_DIR = tmp_path_factory.mktemp("live")
    with TestClient(server.app) as c:
        yield c


def call(c, **body):
    r = c.post("/api/gateway/call", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_health_reports_contract_and_anchored_seed_batch(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and h["contract"].startswith("0x") and len(h["contract"]) == 42
    assert h["anchored_batches"] >= 1 and h["block_number"] >= 2
    assert h["records"]["R1"] == h["records"]["R2"] == h["records"]["R3"] >= 4


def test_gateway_call_returns_full_trace_and_hashes(client):
    ok = call(client, role="analyst", tool="query_db",
              arguments={"query": "SELECT region FROM analytics_sales LIMIT 3"}, session_id="t1")
    assert ok["decision"] == "ALLOW" and [s["status"] for s in ok["stages"]] == ["pass"] * 7
    assert len(ok["audit"]["R3"]["entry_hash"]) == 64 and ok["audit"]["R2"]["entry_hash"] == ok["audit"]["R3"]["entry_hash"]
    bad = call(client, role="analyst", tool="query_db",
               arguments={"query": "SELECT * FROM analytics_sales WHERE region='x' OR 1=1 LIMIT 5"}, session_id="t1")
    assert bad["decision"] == "DENY" and bad["denied_at"] == "ingress" and "SQL_TAUTOLOGY" in bad["triggered_rules"]
    st = {s["stage"]: s["status"] for s in bad["stages"]}
    hidden = call(client, role="analyst", tool="query_db",
                  arguments={"query": "SELECT * FROM analytics_sales WHERE region='x' OR 1=1 -- LIMIT 5"}, session_id="t1")
    assert hidden["denied_at"] == "abac"  # LIMIT hidden in a comment fails the ABAC constraint first
    assert st["ingress"] == "deny" and st["downstream"] == "skipped" and st["audit"] == "pass"


def test_taint_override_and_rugpull_flags(client):
    r = call(client, role="operator", tool="http_post", arguments={"url": "https://api.example.com/x", "body": "hi"},
             session_id="t2", taint_override="TAINTED_SENSITIVE")
    assert r["decision"] == "DENY" and "TAINTED_SENSITIVE" in r["taint_state"]
    r = call(client, role="operator", tool="read_file", arguments={"path": "/workspace/notes.txt"},
             session_id="t3", simulate_rugpull=True)
    assert r["decision"] == "DENY" and r["triggered_rules"] == ["TOOL_INTEGRITY_VIOLATION"]
    r = call(client, role="operator", tool="read_file", arguments={"path": "/workspace/notes.txt"}, session_id="t3")
    assert r["decision"] == "ALLOW"  # the simulated rug-pull is scoped to one call


def test_rejects_bad_requests(client):
    assert client.post("/api/gateway/call", json={"role": "root", "tool": "x"}).status_code == 422
    big = {"content": "x" * 30_000, "path": "/workspace/a"}
    assert client.post("/api/gateway/call", json={"tool": "write_file", "arguments": big}).status_code == 413
    assert client.post("/api/tamper/format_disk").status_code == 404


def test_ledger_lists_rows_batches_and_onchain_matches(client):
    led = client.get("/api/ledger?limit=5").json()
    assert set(led["regimes"]) == {"R1", "R2", "R3"} and len(led["regimes"]["R3"]["rows"]) == 5
    b0 = led["merkle_batches"][0]
    assert b0["status"] == "anchored" and b0["on_chain_match"] is True and b0["tx_hash"].startswith("0x")
    assert led["chain"]["anchored_batches"] == len([b for b in led["merkle_batches"] if b["status"] == "anchored"])


def _fill(client, n=6):
    for i in range(n):
        call(client, role="operator", tool="read_file", arguments={"path": "/workspace/../etc/passwd"}, session_id=f"f{i}")


@pytest.mark.parametrize("attack,expected", [
    ("edit_decision", {"R1": False, "R2": True, "R3": True}),
    ("delete_row", {"R1": True, "R2": True, "R3": True}),
    ("rewrite_chain", {"R1": False, "R2": False, "R3": True}),
    ("truncate_tail", {"R1": False, "R2": False, "R3": True}),
    ("tool_rugpull", {"R1": False, "R2": False, "R3": True}),
])
def test_tamper_then_watcher_detection_matrix(client, attack, expected):
    assert client.post("/api/ledger/reset").json()["status"] == "ok"
    _fill(client)
    clean = client.post("/api/watcher/verify").json()
    assert all(v["ok"] for v in clean["regimes"].values()), clean["summary"]
    applied = client.post(f"/api/tamper/{attack}").json()["applied"]
    assert set(applied) == {"R1", "R2", "R3"}
    res = client.post("/api/watcher/verify").json()["regimes"]
    assert {g: not v["ok"] for g, v in res.items()} == expected
    if attack == "rewrite_chain":
        assert {a["violation"] for a in res["R3"]["alerts"]} >= {"ANCHOR_RECORDS_MISMATCH"}
        assert "HASH_MISMATCH" not in {a["violation"] for a in res["R3"]["alerts"]}  # locally consistent forgery


def test_reset_restores_a_clean_anchored_baseline(client):
    client.post("/api/tamper/delete_row")
    h = client.post("/api/ledger/reset").json()
    assert h["anchored_batches"] == 1 and h["records"]["R3"] == len(server.SEED_CALLS)
    assert all(v["ok"] for v in client.post("/api/watcher/verify").json()["regimes"].values())


def test_metrics_endpoint_serves_results(client):
    m = client.get("/api/metrics").json()
    assert {"engines", "external", "calibration", "tamper", "latency"} <= set(m)
    if m["external"]:
        v12 = m["external"]["prompt_injection_ingress"]["clean"]["v1.2"]
        assert 0.0 <= v12["f1"] <= 1.0 and v12["contaminated_rows"] == 0
