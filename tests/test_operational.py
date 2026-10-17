"""Tests for operational completeness: persistence, events, diagnostics, expansion."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from octopie import (
    Head, HeadConfig, LimitsConfig, NodeState,
    diagnose, explain_rejection,
    EventLog, EventType,
    ExpansionEngine, ExpansionRequest,
    Store, SCHEMA_VERSION,
)
from octopie.identity import make_simulated_identity
from octopie.persistence import build_snapshot_from_head, apply_snapshot_to_head
from octopie.simulation import NetworkSimulator
from octopie.adapters import AdapterRegistry, NullNetworkHealthAdapter, NetworkHealthObservation


def test_config_rejects_network_without_authz():
    with pytest.raises(ValueError, match="require_explicit_authorization"):
        HeadConfig(network_expansion_enabled=True, require_explicit_authorization=False)


def test_config_new_fields():
    cfg = HeadConfig()
    assert cfg.limits.admission_timeout_seconds > 0
    assert cfg.limits.credential_ttl_seconds > 0
    assert cfg.audit.policy_version == "1"
    assert cfg.simulation.seed == 42


def test_event_redaction_and_chain():
    log = EventLog(hash_link=True, policy_version="1")
    log.emit(EventType.NODE_DISCOVERED, outcome="info", node_id="n1", token="secret-value")
    log.emit(EventType.NODE_ADMITTED, outcome="success", node_id="n1")
    assert log.verify_chain() is True
    log._events[1].prev_hash = "tampered"
    assert log.verify_chain() is False


def test_event_sensitive_keys_stripped():
    log = EventLog()
    ev = log.emit(EventType.AUTH_FAILED, outcome="failure", node_id="x", credential="abc", password="xyz")
    assert "abc" not in str(ev.to_dict())
    assert "xyz" not in str(ev.to_dict())


def test_persistence_round_trip():
    with tempfile.TemporaryDirectory() as td:
        cfg = HeadConfig.for_target(4, seed=50)
        head = Head(cfg)
        for i in range(4):
            nid = f"n{i}"
            head.register_and_authorize(make_simulated_identity(nid))
            head.request_admission(nid, head.issue_token(nid), now=1000.0 + i)
        head.revoke("n0")
        snap = build_snapshot_from_head(head)
        assert snap.schema_version == SCHEMA_VERSION
        store = Store(td)
        store.save(snap)
        loaded = store.load()
        assert loaded is not None
        head2 = Head(cfg)
        apply_snapshot_to_head(head2, loaded)
        assert head2.identity.is_revoked("n0")
        assert head2.admitted_count() == 0
        assert head2._admissions_paused is True


def test_persistence_corrupt_fails_safe():
    with tempfile.TemporaryDirectory() as td:
        store = Store(td)
        (Path(td) / "snapshot.json").write_text("{not json")
        with pytest.raises(ValueError, match="corrupt"):
            store.load()


def test_persistence_schema_mismatch():
    with tempfile.TemporaryDirectory() as td:
        store = Store(td)
        bad = {"schema_version": 999, "saved_at": 0, "head_id": "h",
               "policy_version": "1", "authorized_ids": [], "revoked": [], "nodes": []}
        (Path(td) / "snapshot.json").write_text(json.dumps(bad))
        with pytest.raises(ValueError, match="schema version"):
            store.load()


def test_revocation_survives_restore():
    with tempfile.TemporaryDirectory() as td:
        cfg = HeadConfig.for_target(3, seed=51)
        head = Head(cfg)
        for i in range(3):
            nid = f"p{i}"
            head.register_and_authorize(make_simulated_identity(nid))
            head.request_admission(nid, head.issue_token(nid), now=2000.0 + i)
        head.revoke("p1")
        store = Store(td)
        store.save(build_snapshot_from_head(head))
        head2 = Head(cfg)
        apply_snapshot_to_head(head2, store.load())
        assert head2.identity.is_revoked("p1")
        head2.resume_admissions()
        assert head2.request_admission("p1", "any").admitted is False


def test_diagnose_target_achievable():
    cfg = HeadConfig.for_target(4, seed=52)
    sim = NetworkSimulator(cfg)
    sim.bootstrap_identities(4)
    sim.grow_to_target(4)
    report = diagnose(sim.head)
    assert report.admitted == 4
    assert report.target_achievable is True
    assert report.topology_consistent is True


def test_diagnose_unachievable_when_few_authorized():
    cfg = HeadConfig.for_target(8, seed=53)
    head = Head(cfg)
    for i in range(2):
        head.register_and_authorize(make_simulated_identity(f"q{i}"))
    report = diagnose(head)
    assert report.target_achievable is False
    assert any("authorized" in f for f in report.limiting_factors)


def test_explain_rejection():
    head = Head(HeadConfig(seed=54))
    assert "never discovered" in explain_rejection(head, "missing")
    head.topology.add_discovered("only")
    msg = explain_rejection(head, "only")
    assert "unknown" in msg or "DISCOVERED" in msg or "not" in msg


def test_expansion_idempotent():
    cfg = HeadConfig.for_target(4, seed=55)
    head = Head(cfg)
    nid = "exp-0"
    head.register_and_authorize(make_simulated_identity(nid))
    token = head.issue_token(nid)
    eng = ExpansionEngine(head)
    r1 = eng.expand_one(ExpansionRequest(nid, token), now=3000.0)
    r2 = eng.expand_one(ExpansionRequest(nid, token), now=3001.0)
    assert r1.admitted is True
    assert r2.admitted is True
    assert r2.reason == "already_admitted"


def test_expansion_backpressure_capacity():
    limits = LimitsConfig(max_nodes=2, max_expansion_per_second=100.0)
    cfg = HeadConfig(target_nodes=2, limits=limits, seed=56)
    head = Head(cfg)
    eng = ExpansionEngine(head)
    outcomes = []
    for i in range(5):
        nid = f"bp{i}"
        head.register_and_authorize(make_simulated_identity(nid))
        token = head.issue_token(nid)
        outcomes.append(eng.expand_one(ExpansionRequest(nid, token), now=4000.0 + i * 0.01))
    assert sum(1 for o in outcomes if o.admitted) == 2
    assert any(o.reason == "capacity_exceeded" for o in outcomes)


def test_expansion_cancel():
    cfg = HeadConfig.for_target(4, seed=57)
    head = Head(cfg)
    eng = ExpansionEngine(head)
    eng.cancel()
    nid = "c0"
    head.register_and_authorize(make_simulated_identity(nid))
    out = eng.expand_one(ExpansionRequest(nid, head.issue_token(nid)))
    assert out.admitted is False
    assert out.phase.name == "CANCELLED"


def test_simulation_summary_reproducible():
    def run(seed):
        return NetworkSimulator(HeadConfig.for_target(8, seed=seed)).run_full_scenario(8)
    a, b = run(77), run(77)
    assert a.seed == b.seed == 77
    assert a.admitted == b.admitted
    assert a.target == 8
    assert "rejection_reasons" in a.to_dict()


def test_null_adapters():
    reg = AdapterRegistry()
    data = reg.collect_all()
    assert data["network_health"] == []
    assert NullNetworkHealthAdapter().name() == "null-network-health"


def test_observation_dataclass():
    obs = NetworkHealthObservation(source="test", timestamp=1.0, path_id="p1", latency_ms=12.0)
    assert obs.reachable is True


def test_existing_42_still_works():
    cfg = HeadConfig.for_target(42, seed=42)
    sim = NetworkSimulator(cfg)
    sim.bootstrap_identities(42)
    assert sim.grow_to_target(42) == 42
