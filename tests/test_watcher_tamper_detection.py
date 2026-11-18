import json
import random
import shutil
import sqlite3
import subprocess
import sys

import pytest
from conftest import ANALYST, OPERATOR, call

from omniguard.agents.gateway_agent import build_stack
from omniguard.agents.watcher_agent import IntegrityWatcher
from omniguard.config import PINNED_TOOLS_PATH
from omniguard.crypto.chain_node import ChainNodeProcess
from omniguard.evaluation import tamper_experiments as T
from omniguard.models import AuditEvent
from omniguard.storage.audit_store import AuditStore


def populate(gw, n=40):
    for i in range(n):
        if i % 4 == 0:
            call(gw, OPERATOR, "read_file", {"path": "/workspace/../etc/passwd"}, rid=i)
        else:
            call(gw, ANALYST, "query_db", {"query": f"SELECT region FROM analytics_sales LIMIT {i + 1}"}, rid=i)


@pytest.fixture
def r3_log(stack_factory, tmp_path):
    st = stack_factory("R3", batch_size=8)
    populate(st.gateway)
    st.audit.flush()
    st.store.close()
    w3 = st.audit.anchor.w3

    def sweep(db, **kw):
        return IntegrityWatcher(db, "R3", contract_address=st.contract_address, w3=w3,
                                manifest_snapshot=PINNED_TOOLS_PATH, **kw).sweep()

    return st.store.path, sweep, tmp_path


def copy_of(src, tmp_path, name):
    dst = tmp_path / f"{name}.db"
    shutil.copyfile(src, dst)
    return dst


def violations(rep):
    return {a.violation for a in rep.alerts}


def test_clean_log_has_no_alerts(r3_log):
    db, sweep, _ = r3_log
    rep = sweep(db)
    assert rep.ok, rep.alerts
    assert rep.records_checked == 40 and rep.batches_checked == 5
    assert rep.checks == ["hash_chain", "merkle_roots", "chain_anchors", "manifest_drift"]


@pytest.mark.parametrize("fn,expected", [
    (T.tamper_field_modification, {"HASH_MISMATCH", "MERKLE_ROOT_MISMATCH", "ANCHOR_RECORDS_MISMATCH"}),
    (T.tamper_record_deletion, {"SEQUENCE_GAP", "CHAIN_BREAK"}),
    (T.tamper_tail_truncation, {"TAIL_TRUNCATION", "ANCHORED_BATCH_MISSING"}),
    (T.tamper_reorder, {"HASH_MISMATCH"}),
    (T.tamper_root_forgery, {"ANCHOR_ROOT_MISMATCH", "ANCHOR_RECORDS_MISMATCH"}),
])
def test_r3_detects_every_log_tamper(r3_log, fn, expected):
    db, sweep, tmp = r3_log
    t = copy_of(db, tmp, fn.__name__)
    fn(t, AuditStore(t, "R3", read_only=True).regime, random.Random(1), batch_size=8, trial_dir=tmp)
    found = violations(sweep(t))
    assert expected <= found, found


def test_forgery_passes_chain_and_merkle_checks_but_not_the_anchor(r3_log):
    db, sweep, tmp = r3_log
    t = copy_of(db, tmp, "forge")
    T.tamper_root_forgery(t, AuditStore(t, "R3", read_only=True).regime, random.Random(3))
    found = violations(sweep(t))
    assert not found & {"HASH_MISMATCH", "CHAIN_BREAK", "MERKLE_ROOT_MISMATCH"}  # locally consistent forgery
    assert "ANCHOR_RECORDS_MISMATCH" in found


def test_manifest_drift_detected_from_registry_and_live_server(r3_log):
    db, sweep, tmp = r3_log
    t = copy_of(db, tmp, "rug")
    T.tamper_rugpull_insider(t, AuditStore(t, "R3", read_only=True).regime, random.Random(0), trial_dir=tmp)
    found = violations(sweep(t))
    assert {"MANIFEST_DRIFT", "REGISTRY_PIN_REWRITTEN"} <= found
    live = sweep(db, tools_cmd=[sys.executable, "-m", "omniguard.tools.sample_mcp_server", "--overrides",
                                str(tmp / "tool_overrides.json")])
    assert any(a.violation == "MANIFEST_DRIFT" and "live_downstream" in a.detail for a in live.alerts)


@pytest.mark.parametrize("regime,fn,detected", [
    ("R1", T.tamper_field_modification, False),
    ("R1", T.tamper_record_deletion, True),  # autoincrement id gap
    ("R2", T.tamper_field_modification, True),
    ("R2", T.tamper_tail_truncation, False),  # a valid prefix of a hash chain is still a valid chain
    ("R2", T.tamper_root_forgery, False),  # recomputed chain is self-consistent
])
def test_weaker_regimes_have_the_expected_blind_spots(stack_factory, tmp_path, regime, fn, detected):
    st = stack_factory(regime)
    populate(st.gateway, 24)
    st.store.close()
    t = copy_of(st.store.path, tmp_path, "t")
    fn(t, st.store.regime, random.Random(2), batch_size=8, trial_dir=tmp_path)
    assert (not IntegrityWatcher(t, regime).sweep().ok) is detected


def test_watcher_connection_is_read_only(r3_log):
    db, _, _ = r3_log
    ro = AuditStore.open_readonly(db, "R3")
    with pytest.raises(PermissionError):
        ro.append(AuditEvent(event_type="x"))
    with pytest.raises(sqlite3.OperationalError):
        ro.conn.execute("DELETE FROM audit_logs_r3")
    ro.conn.close()


def test_watcher_runs_as_independent_process(tmp_path, subprocess_env):
    with ChainNodeProcess() as node:
        st = build_stack("R3", tmp_path / "gw.db", rpc_url=node.url, batch_size=8)
        populate(st.gateway, 20)
        st.audit.flush()
        st.store.close()
        snap = tmp_path / "snapshot.json"
        shutil.copyfile(PINNED_TOOLS_PATH, snap)
        cmd = [sys.executable, "-m", "omniguard.agents.watcher_agent", "--db", str(st.store.path), "--regime", "R3",
               "--rpc-url", node.url, "--contract", st.contract_address, "--manifest-snapshot", str(snap), "--json"]
        ok = subprocess.run(cmd, capture_output=True, text=True, env=subprocess_env, timeout=120)
        rep = json.loads(ok.stdout.strip().splitlines()[-1])
        assert ok.returncode == 0 and rep["ok"] and rep["records_checked"] == 20

        T.tamper_tail_truncation(st.store.path, st.store.regime, random.Random(0), batch_size=8)
        bad = subprocess.run(cmd, capture_output=True, text=True, env=subprocess_env, timeout=120)
        rep = json.loads(bad.stdout.strip().splitlines()[-1])
        assert bad.returncode == 2 and not rep["ok"]
        assert "TAIL_TRUNCATION" in {a["violation"] for a in rep["alerts"]}
        assert "TamperAlert" in bad.stderr
