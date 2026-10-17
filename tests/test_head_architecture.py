"""Test suite for Octopie head architecture.

Covers the 14 required verification points plus compatibility checks.
"""

from __future__ import annotations

import pytest

from octopie import Head, HeadConfig, LimitsConfig, NodeState
from octopie.admission import RejectionReason
from octopie.config import HeadConfig
from octopie.identity import make_simulated_identity, CredentialStatus
from octopie.simulation import NetworkSimulator


@pytest.mark.parametrize("n", [8, 16, 32, 42, 64])
def test_manage_n_authorized_nodes(n: int):
    cfg = HeadConfig.for_target(n, seed=123)
    sim = NetworkSimulator(cfg)
    sim.bootstrap_identities(n)
    admitted = sim.grow_to_target(n)
    assert admitted == n
    assert sim.head.admitted_count() == n
    assert sim.head.config.limits.max_nodes >= n


def test_default_target_is_42():
    cfg = HeadConfig()
    assert cfg.target_nodes == 42
    assert cfg.limits.max_nodes >= 42


def test_unauthenticated_rejected():
    sim = NetworkSimulator(HeadConfig(seed=1, target_nodes=8))
    sim.bootstrap_identities(4)
    assert sim.inject_unauthenticated() is True


def test_unauthorized_rejected():
    sim = NetworkSimulator(HeadConfig(seed=2, target_nodes=8))
    assert sim.inject_unauthorized() is True


def test_revocation():
    cfg = HeadConfig.for_target(8, seed=3)
    sim = NetworkSimulator(cfg)
    sim.bootstrap_identities(8)
    sim.grow_to_target(8)
    victim = sim._node_ids[0]
    assert sim.revoke_and_verify(victim) is True
    assert sim.head.topology.get(victim).state == NodeState.REVOKED


def test_peer_cannot_confer_trust():
    sim = NetworkSimulator(HeadConfig(seed=4, target_nodes=4))
    sim.bootstrap_identities(2)
    sim.grow_to_target(2)
    assert sim.peer_cannot_confer_trust() is True


def test_duplicate_admission_rejected():
    cfg = HeadConfig.for_target(4, seed=5)
    sim = NetworkSimulator(cfg)
    sim.bootstrap_identities(4)
    sim.grow_to_target(2)
    node = sim._node_ids[0]
    token = sim._tokens[node]
    result = sim.head.request_admission(node, token)
    assert result.admitted is False
    assert result.reason == RejectionReason.ALREADY_ADMITTED


def test_replay_nonce_rejected():
    cfg = HeadConfig.for_target(4, seed=6)
    head = Head(cfg)
    identity = make_simulated_identity("n1")
    head.register_and_authorize(identity)
    token = head.issue_token("n1")
    r1 = head.request_admission("n1", token, nonce="nonce-abc")
    assert r1.admitted is True
    status2 = head.identity.verify_credential("n1", token, nonce="nonce-abc")
    assert status2 == CredentialStatus.UNKNOWN


def test_node_capacity_limit():
    limits = LimitsConfig(max_nodes=3, max_expansion_per_second=100.0)
    cfg = HeadConfig(target_nodes=3, limits=limits, seed=7)
    sim = NetworkSimulator(cfg)
    sim.bootstrap_identities(5)
    admitted = sim.grow_to_target(5)
    assert admitted == 3
    assert sim.head.admitted_count() == 3


def test_rate_limit():
    limits = LimitsConfig(max_nodes=20, max_expansion_per_second=2.0, max_concurrent_admissions=2)
    cfg = HeadConfig(target_nodes=10, limits=limits, seed=8)
    head = Head(cfg)
    for i in range(5):
        nid = f"rate-{i}"
        head.register_and_authorize(make_simulated_identity(nid))
        token = head.issue_token(nid)
        head.request_admission(nid, token, now=1000.0)
    assert head.admitted_count() <= 2


def test_bounded_recovery():
    cfg = HeadConfig.for_target(4, seed=9)
    object.__setattr__(cfg.limits, "recovery_max_attempts", 2)
    sim = NetworkSimulator(cfg)
    sim.bootstrap_identities(4)
    sim.grow_to_target(4)
    victim = sim._node_ids[1]
    assert sim.run_failure_and_recovery(victim) is True
    assert sim.head.admitted_count() <= 4


def test_head_loss_pauses_admissions():
    sim = NetworkSimulator(HeadConfig(seed=10, target_nodes=4))
    sim.bootstrap_identities(4)
    sim.grow_to_target(2)
    assert sim.head_loss_pauses_admissions() is True
    assert sim.head.is_available is True


def test_invalid_config_fails_closed():
    with pytest.raises(ValueError):
        LimitsConfig(max_nodes=0)
    with pytest.raises(ValueError):
        HeadConfig(head_id="")
    with pytest.raises(ValueError):
        HeadConfig(target_nodes=0)


def test_reproducible_simulation():
    def run(seed: int):
        cfg = HeadConfig.for_target(8, seed=seed)
        sim = NetworkSimulator(cfg)
        sim.bootstrap_identities(8)
        return sim.grow_to_target(8), sim.head.status()

    a = run(99)
    b = run(99)
    assert a[0] == b[0]
    assert a[1]["admitted"] == b[1]["admitted"]


def test_audit_redacts_secrets():
    head = Head(HeadConfig(seed=11))
    head.audit.record("test", node_id="n1", token="super-secret-token", reason="ok")
    events = head.audit.events()
    assert len(events) == 1
    assert events[0]["token"] == "[REDACTED]"
    assert "super-secret" not in str(events)


def test_public_api_smoke():
    from octopie import (
        Head,
        HeadConfig,
        LimitsConfig,
        NodeState,
        NodeRecord,
        IdentityStore,
        NodeIdentity,
        AdmissionResult,
        RejectionReason,
        __version__,
    )
    assert __version__
    h = Head()
    h.start()
    assert h.status()["running"] is True
    h.shutdown()
    assert h.is_available is False


def test_discovery_does_not_imply_admission():
    head = Head(HeadConfig(seed=12))
    head.topology.add_discovered("only-discovered")
    rec = head.topology.get("only-discovered")
    assert rec.state == NodeState.DISCOVERED
    assert rec.can_transition_to(NodeState.ADMITTED) is False
