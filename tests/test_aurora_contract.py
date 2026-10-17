"""Contract tests: Octopie ↔ Aurora integration boundary."""

from __future__ import annotations

import json
import time

import pytest

from octopie import Head, HeadConfig
from octopie.contract import (
    CONTRACT_VERSION, AdmissionDecision, AdmissionRequested, ContractError,
    DecisionOutcome, MembershipSnapshot, NodeObserved, NodeRevocation,
    TrustOutcome, parse_decision, serialize,
)
from octopie.aurora_bridge import DecisionService, FakeAuroraAdapter, bootstrap_authorized
from octopie.simulation import NetworkSimulator


def test_contract_version_constant():
    assert CONTRACT_VERSION == "octopie-aurora/1.0"


def test_node_observed_round_trip():
    obs = NodeObserved(node_id="n1", observed_at=1.0, reachable=True)
    back = NodeObserved.from_dict(json.loads(serialize(obs)))
    assert back.node_id == "n1"
    assert back.contract_version == CONTRACT_VERSION


def test_incompatible_version_rejected():
    with pytest.raises(ContractError, match="incompatible_contract_version"):
        NodeObserved.from_dict({"node_id": "x", "observed_at": 1.0, "contract_version": "octopie-aurora/9.9"})


def test_discovered_is_not_trusted():
    head = Head(HeadConfig(seed=1))
    svc = DecisionService(head)
    aurora = FakeAuroraAdapter()
    obs = aurora.observe_node("peer-1")
    assert svc.ingest_observation(obs) == TrustOutcome.OBSERVED_UNVERIFIED
    assert head.admitted_count() == 0
    assert "peer-1" not in svc.membership_snapshot().admitted_node_ids


def test_admission_requires_credential():
    head = Head(HeadConfig.for_target(4, seed=2))
    svc = DecisionService(head)
    decision = svc.handle_admission_request(AdmissionRequested(node_id="n1", requested_at=time.time()), token=None)
    assert decision.outcome == DecisionOutcome.REJECT
    assert decision.reason_code == "missing_credential"


def test_valid_admission_decision():
    head = Head(HeadConfig.for_target(4, seed=3))
    tokens = bootstrap_authorized(head, ["n0", "n1"])
    svc = DecisionService(head)
    decision = svc.handle_admission_request(
        AdmissionRequested(node_id="n0", requested_at=1000.0, correlation_id="c-1"),
        token=tokens["n0"], now=1000.0,
    )
    assert decision.outcome == DecisionOutcome.ADMIT
    assert decision.trust_outcome == TrustOutcome.ADMITTED_ACTIVE
    assert "n0" in svc.membership_snapshot().admitted_node_ids
    assert "n1" not in svc.membership_snapshot().admitted_node_ids


def test_duplicate_correlation_idempotent():
    head = Head(HeadConfig.for_target(4, seed=4))
    tokens = bootstrap_authorized(head, ["n0"])
    svc = DecisionService(head)
    req = AdmissionRequested(node_id="n0", requested_at=1.0, correlation_id="dup-1")
    d1 = svc.handle_admission_request(req, token=tokens["n0"], now=1.0)
    d2 = svc.handle_admission_request(req, token=tokens["n0"], now=2.0)
    assert d1.correlation_id == d2.correlation_id
    assert head.admitted_count() == 1


def test_revocation_message():
    head = Head(HeadConfig.for_target(4, seed=5))
    tokens = bootstrap_authorized(head, ["n0"])
    svc = DecisionService(head)
    svc.handle_admission_request(AdmissionRequested(node_id="n0", requested_at=1.0), token=tokens["n0"], now=1.0)
    rev = svc.revoke("n0", reason="compromise")
    assert isinstance(rev, NodeRevocation)
    assert "n0" not in svc.membership_snapshot().admitted_node_ids
    d = svc.handle_admission_request(
        AdmissionRequested(node_id="n0", requested_at=2.0, correlation_id="re"),
        token=tokens["n0"], now=2.0,
    )
    assert d.outcome == DecisionOutcome.REJECT


def test_stale_decision_expired():
    head = Head(HeadConfig.for_target(2, seed=6))
    tokens = bootstrap_authorized(head, ["n0"])
    svc = DecisionService(head, decision_ttl_seconds=10.0)
    d = svc.handle_admission_request(
        AdmissionRequested(node_id="n0", requested_at=100.0), token=tokens["n0"], now=100.0,
    )
    assert d.is_expired(now=100.0) is False
    assert d.is_expired(now=200.0) is True


def test_parse_malformed_decision():
    with pytest.raises(Exception):
        parse_decision('{"node_id":"x"}')


def test_outage_pauses_admissions():
    head = Head(HeadConfig.for_target(4, seed=7))
    tokens = bootstrap_authorized(head, ["n0"])
    svc = DecisionService(head)
    head.simulate_head_loss()
    d = svc.handle_admission_request(
        AdmissionRequested(node_id="n0", requested_at=1.0), token=tokens["n0"], now=1.0,
    )
    assert d.outcome == DecisionOutcome.REJECT
    assert svc.status().admissions_paused is True


def test_transport_success_is_not_trust():
    head = Head(HeadConfig(seed=8))
    svc = DecisionService(head)
    aurora = FakeAuroraAdapter()
    for i in range(5):
        aurora.observe_node(f"mesh-{i}")
        svc.ingest_observation(aurora.poll_observations()[-1])
    assert svc.membership_snapshot().admitted_node_ids == []


def test_simulation_42_via_contract_path():
    sim = NetworkSimulator(HeadConfig.for_target(42, seed=42))
    sim.bootstrap_identities(42)
    assert sim.grow_to_target(42) == 42
    assert len(DecisionService(sim.head).membership_snapshot().admitted_node_ids) == 42


def test_simulation_above_42():
    sim = NetworkSimulator(HeadConfig.for_target(64, seed=9))
    sim.bootstrap_identities(64)
    assert sim.grow_to_target(64) == 64


def test_decision_serialization_no_secrets():
    head = Head(HeadConfig.for_target(2, seed=10))
    tokens = bootstrap_authorized(head, ["n0"])
    svc = DecisionService(head)
    d = svc.handle_admission_request(
        AdmissionRequested(node_id="n0", requested_at=1.0), token=tokens["n0"], now=1.0,
    )
    raw = serialize(d)
    assert tokens["n0"] not in raw
