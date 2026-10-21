"""Adversarial and regression tests for trust-gated service naming v0.1."""

from __future__ import annotations

import json
import time

import pytest

from octopie import Head, HeadConfig
from octopie.contract import CONTRACT_VERSION, ContractError, serialize
from octopie.identity import make_simulated_identity
from octopie.naming import (
    CAPABILITY_PUBLISH_SERVICE,
    BindingStatus,
    EndpointRef,
    InMemoryBindingStore,
    NamingService,
    PublicationOutcome,
    ServiceBindingLookupRequest,
    ServicePublicationRequest,
    canonicalize_service_name,
    stable_service_id,
)
from octopie.aurora_bridge import bootstrap_authorized


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _head_and_naming(seed: int = 1, caps=None):
    head = Head(HeadConfig(seed=seed))
    caps = frozenset(caps or {CAPABILITY_PUBLISH_SERVICE, "worker"})
    identity = make_simulated_identity("pub-1", capabilities=set(caps))
    head.register_and_authorize(identity)
    naming = NamingService(head.identity, policy_version=head.config.audit.policy_version)
    token = head.issue_token("pub-1")
    return head, naming, token


def _ep(eid: str = "ep-1") -> EndpointRef:
    return EndpointRef(endpoint_id=eid, transport_hint="mesh")


# ---------------------------------------------------------------------------
# Name canonicalization
# ---------------------------------------------------------------------------

def test_canonicalize_valid():
    assert canonicalize_service_name("My.Service") == "my.service"
    assert canonicalize_service_name("alpha_beta") == "alpha_beta"


def test_canonicalize_rejects_malformed():
    with pytest.raises(ValueError):
        canonicalize_service_name("")
    with pytest.raises(ValueError):
        canonicalize_service_name("1bad")
    with pytest.raises(ValueError):
        canonicalize_service_name("has spaces")
    with pytest.raises(ValueError):
        canonicalize_service_name("a" * 100)


def test_stable_service_id_independent_of_endpoint():
    a = stable_service_id("svc.alpha", "owner-1")
    b = stable_service_id("svc.alpha", "owner-1")
    c = stable_service_id("svc.alpha", "owner-2")
    assert a == b
    assert a != c


# ---------------------------------------------------------------------------
# Authorization gates
# ---------------------------------------------------------------------------

def test_unauthorized_publication_rejected():
    head = Head(HeadConfig(seed=2))
    naming = NamingService(head.identity)
    head.identity.register_identity(make_simulated_identity("ghost"))
    req = ServicePublicationRequest(
        service_name="svc.test", publisher_id="ghost",
        endpoints=[_ep()], requested_at=1000.0,
    )
    d = naming.publish(req, now=1000.0)
    assert d.outcome == PublicationOutcome.REJECTED
    assert d.reason_code == "publisher_not_authorized"


def test_unknown_publisher_rejected():
    head, naming, _ = _head_and_naming(3)
    req = ServicePublicationRequest(
        service_name="svc.test", publisher_id="nobody",
        endpoints=[_ep()], requested_at=1000.0,
    )
    d = naming.publish(req, now=1000.0)
    assert d.outcome == PublicationOutcome.REJECTED
    assert d.reason_code == "unknown_publisher"


def test_revoked_publisher_cannot_publish():
    head, naming, token = _head_and_naming(4)
    head.identity.revoke("pub-1")
    req = ServicePublicationRequest(
        service_name="svc.test", publisher_id="pub-1",
        endpoints=[_ep()], requested_at=1000.0,
    )
    d = naming.publish(req, token=token, now=1000.0)
    assert d.outcome == PublicationOutcome.REJECTED
    assert d.reason_code == "publisher_revoked"


def test_discovered_but_unverified_cannot_publish():
    """Discovery (topology only) never grants publish rights."""
    head = Head(HeadConfig(seed=5))
    head.topology.add_discovered("mesh-peer")
    naming = NamingService(head.identity)
    req = ServicePublicationRequest(
        service_name="svc.mesh", publisher_id="mesh-peer",
        endpoints=[_ep()], requested_at=1000.0,
    )
    d = naming.publish(req, now=1000.0)
    assert d.outcome == PublicationOutcome.REJECTED
    assert d.reason_code in {"unknown_publisher", "publisher_not_authorized"}


def test_missing_capability_rejected_when_scoped():
    head = Head(HeadConfig(seed=6))
    identity = make_simulated_identity("pub-limited", capabilities={"worker"})
    head.register_and_authorize(identity)
    naming = NamingService(head.identity)
    req = ServicePublicationRequest(
        service_name="svc.limited", publisher_id="pub-limited",
        endpoints=[_ep()], requested_at=1000.0,
    )
    d = naming.publish(req, now=1000.0)
    assert d.outcome == PublicationOutcome.REJECTED
    assert d.reason_code == "missing_capability_publish_service"


def test_lookup_does_not_grant_publish():
    head, naming, token = _head_and_naming(7)
    pub = ServicePublicationRequest(
        service_name="svc.look", publisher_id="pub-1",
        endpoints=[_ep()], requested_at=1000.0, correlation_id="c1",
    )
    d = naming.publish(pub, token=token, now=1000.0)
    assert d.outcome == PublicationOutcome.ACCEPTED

    head.identity.register_identity(make_simulated_identity("other"))
    head.identity.authorize("other")
    head.identity._identities["other"] = make_simulated_identity(
        "other", capabilities={CAPABILITY_PUBLISH_SERVICE}
    )
    takeover = ServicePublicationRequest(
        service_name="svc.look", publisher_id="other",
        endpoints=[_ep("ep-hijack")], requested_at=1001.0, correlation_id="c2",
    )
    d2 = naming.publish(takeover, now=1001.0)
    assert d2.outcome == PublicationOutcome.REJECTED
    assert d2.reason_code == "ownership_mismatch"


# ---------------------------------------------------------------------------
# Naming integrity
# ---------------------------------------------------------------------------

def test_successful_publication_and_lookup():
    head, naming, token = _head_and_naming(8)
    req = ServicePublicationRequest(
        service_name="Field.Kernel", publisher_id="pub-1",
        endpoints=[_ep("ep-a"), _ep("ep-b")], requested_at=2000.0,
        lease_seconds=600.0, correlation_id="pub-ok",
    )
    d = naming.publish(req, token=token, now=2000.0)
    assert d.outcome == PublicationOutcome.ACCEPTED
    assert d.binding is not None
    assert d.binding.service_name == "field.kernel"
    assert d.binding.owner_id == "pub-1"
    assert d.binding.binding_version == 1
    assert len(d.binding.endpoints) == 2
    assert d.binding.is_trusted_active(2000.0)

    look = naming.lookup(
        ServiceBindingLookupRequest(service_name="field.kernel", requested_at=2001.0),
        now=2001.0,
    )
    assert look.found is True
    assert look.binding.service_id == d.binding.service_id


def test_endpoint_change_preserves_service_identity():
    head, naming, token = _head_and_naming(9)
    r1 = ServicePublicationRequest(
        service_name="svc.mig", publisher_id="pub-1",
        endpoints=[_ep("ep-old")], requested_at=3000.0, correlation_id="m1",
    )
    d1 = naming.publish(r1, token=token, now=3000.0)
    svc_id = d1.binding.service_id

    r2 = ServicePublicationRequest(
        service_name="svc.mig", publisher_id="pub-1",
        endpoints=[_ep("ep-new")], requested_at=3001.0,
        expected_version=1, correlation_id="m2",
    )
    d2 = naming.publish(r2, token=token, now=3001.0)
    assert d2.outcome == PublicationOutcome.ACCEPTED
    assert d2.binding.service_id == svc_id
    assert d2.binding.binding_version == 2
    assert d2.binding.endpoints[0].endpoint_id == "ep-new"


def test_stale_version_cannot_overwrite():
    head, naming, token = _head_and_naming(10)
    r1 = ServicePublicationRequest(
        service_name="svc.ver", publisher_id="pub-1",
        endpoints=[_ep()], requested_at=4000.0, correlation_id="v1",
    )
    naming.publish(r1, token=token, now=4000.0)
    r2 = ServicePublicationRequest(
        service_name="svc.ver", publisher_id="pub-1",
        endpoints=[_ep("ep2")], requested_at=4001.0,
        expected_version=1, correlation_id="v2",
    )
    naming.publish(r2, token=token, now=4001.0)
    r3 = ServicePublicationRequest(
        service_name="svc.ver", publisher_id="pub-1",
        endpoints=[_ep("ep3")], requested_at=4002.0,
        expected_version=1, correlation_id="v3",
    )
    d3 = naming.publish(r3, token=token, now=4002.0)
    assert d3.outcome == PublicationOutcome.CONFLICT
    assert d3.reason_code == "stale_binding_version"


def test_unauthorized_name_takeover_prevented():
    head, naming, token = _head_and_naming(11)
    naming.publish(
        ServicePublicationRequest(
            service_name="svc.owned", publisher_id="pub-1",
            endpoints=[_ep()], requested_at=5000.0, correlation_id="o1",
        ),
        token=token, now=5000.0,
    )
    identity2 = make_simulated_identity("pub-2", capabilities={CAPABILITY_PUBLISH_SERVICE})
    head.register_and_authorize(identity2)
    d = naming.publish(
        ServicePublicationRequest(
            service_name="svc.owned", publisher_id="pub-2",
            endpoints=[_ep("hijack")], requested_at=5001.0, correlation_id="o2",
        ),
        now=5001.0,
    )
    assert d.outcome == PublicationOutcome.REJECTED
    assert d.reason_code == "ownership_mismatch"


def test_revoked_name_not_silently_reassigned():
    head, naming, token = _head_and_naming(12)
    naming.publish(
        ServicePublicationRequest(
            service_name="svc.rev", publisher_id="pub-1",
            endpoints=[_ep()], requested_at=6000.0, correlation_id="r1",
        ),
        token=token, now=6000.0,
    )
    naming.revoke("svc.rev", revoked_by="pub-1", now=6001.0)
    d = naming.publish(
        ServicePublicationRequest(
            service_name="svc.rev", publisher_id="pub-1",
            endpoints=[_ep()], requested_at=6002.0, correlation_id="r2",
        ),
        token=token, now=6002.0,
    )
    assert d.outcome == PublicationOutcome.REJECTED
    assert d.reason_code == "binding_revoked"


def test_multiple_endpoints_same_identity():
    head, naming, token = _head_and_naming(13)
    eps = [_ep(f"ep-{i}") for i in range(5)]
    d = naming.publish(
        ServicePublicationRequest(
            service_name="svc.multi", publisher_id="pub-1",
            endpoints=eps, requested_at=7000.0, correlation_id="mu",
        ),
        token=token, now=7000.0,
    )
    assert d.outcome == PublicationOutcome.ACCEPTED
    assert len(d.binding.endpoints) == 5


# ---------------------------------------------------------------------------
# Lifecycle: leases, expiry, renewal
# ---------------------------------------------------------------------------

def test_lease_expiry_hides_binding():
    head, naming, token = _head_and_naming(14)
    naming.publish(
        ServicePublicationRequest(
            service_name="svc.lease", publisher_id="pub-1",
            endpoints=[_ep()], requested_at=8000.0,
            lease_seconds=10.0, correlation_id="l1",
        ),
        token=token, now=8000.0,
    )
    look_ok = naming.lookup(
        ServiceBindingLookupRequest(service_name="svc.lease", requested_at=8005.0),
        now=8005.0,
    )
    assert look_ok.found is True

    look_exp = naming.lookup(
        ServiceBindingLookupRequest(service_name="svc.lease", requested_at=8015.0),
        now=8015.0,
    )
    assert look_exp.found is False
    assert look_exp.reason_code == "expired"


def test_renewal_requires_authorization():
    head, naming, token = _head_and_naming(15)
    naming.publish(
        ServicePublicationRequest(
            service_name="svc.ren", publisher_id="pub-1",
            endpoints=[_ep()], requested_at=9000.0,
            lease_seconds=30.0, correlation_id="rn1",
        ),
        token=token, now=9000.0,
    )
    d = naming.publish(
        ServicePublicationRequest(
            service_name="svc.ren", publisher_id="pub-1",
            endpoints=[_ep()], requested_at=9010.0,
            lease_seconds=30.0, correlation_id="rn2",
        ),
        token=token, now=9010.0,
    )
    assert d.outcome in {PublicationOutcome.ACCEPTED, PublicationOutcome.IDEMPOTENT}
    assert d.binding.is_trusted_active(9010.0)

    head.identity.revoke("pub-1")
    d2 = naming.publish(
        ServicePublicationRequest(
            service_name="svc.ren", publisher_id="pub-1",
            endpoints=[_ep()], requested_at=9020.0, correlation_id="rn3",
        ),
        now=9020.0,
    )
    assert d2.outcome == PublicationOutcome.REJECTED


def test_revocation_invalidates_lookup():
    head, naming, token = _head_and_naming(16)
    naming.publish(
        ServicePublicationRequest(
            service_name="svc.gone", publisher_id="pub-1",
            endpoints=[_ep()], requested_at=10000.0, correlation_id="g1",
        ),
        token=token, now=10000.0,
    )
    rev = naming.revoke("svc.gone", revoked_by="pub-1", reason_code="compromise", now=10001.0)
    assert rev is not None
    look = naming.lookup(
        ServiceBindingLookupRequest(service_name="svc.gone", requested_at=10002.0),
        now=10002.0,
    )
    assert look.found is False
    assert look.reason_code == "revoked"


def test_owner_revocation_cascades_bindings():
    head, naming, token = _head_and_naming(17)
    for i in range(3):
        naming.publish(
            ServicePublicationRequest(
                service_name=f"svc.cascade{i}", publisher_id="pub-1",
                endpoints=[_ep()], requested_at=11000.0 + i, correlation_id=f"c{i}",
            ),
            token=token, now=11000.0 + i,
        )
    revs = naming.revoke_owner_bindings("pub-1", now=11100.0)
    assert len(revs) == 3
    for i in range(3):
        look = naming.lookup(
            ServiceBindingLookupRequest(service_name=f"svc.cascade{i}", requested_at=11101.0),
            now=11101.0,
        )
        assert look.found is False


# ---------------------------------------------------------------------------
# Protocol robustness
# ---------------------------------------------------------------------------

def test_serialization_round_trip_no_secrets():
    head, naming, token = _head_and_naming(18)
    d = naming.publish(
        ServicePublicationRequest(
            service_name="svc.ser", publisher_id="pub-1",
            endpoints=[_ep()], requested_at=12000.0, correlation_id="s1",
        ),
        token=token, now=12000.0,
    )
    raw = serialize(d)
    assert token not in raw
    assert "secret" not in raw.lower()
    back = type(d).from_dict(json.loads(raw))
    assert back.outcome == d.outcome
    assert back.binding.service_id == d.binding.service_id


def test_incompatible_version_rejected():
    with pytest.raises(ContractError, match="incompatible_contract_version"):
        ServicePublicationRequest.from_dict({
            "service_name": "x", "publisher_id": "y",
            "endpoints": [{"endpoint_id": "e"}],
            "requested_at": 1.0,
            "contract_version": "octopie-aurora/9.9",
        })


def test_missing_endpoints_rejected():
    head, naming, token = _head_and_naming(19)
    d = naming.publish(
        ServicePublicationRequest(
            service_name="svc.empty", publisher_id="pub-1",
            endpoints=[], requested_at=13000.0, correlation_id="e1",
        ),
        token=token, now=13000.0,
    )
    assert d.outcome == PublicationOutcome.REJECTED
    assert d.reason_code == "missing_endpoints"


def test_duplicate_correlation_idempotent():
    head, naming, token = _head_and_naming(20)
    req = ServicePublicationRequest(
        service_name="svc.dup", publisher_id="pub-1",
        endpoints=[_ep()], requested_at=14000.0, correlation_id="dup-x",
    )
    d1 = naming.publish(req, token=token, now=14000.0)
    d2 = naming.publish(req, token=token, now=14001.0)
    assert d1.outcome == PublicationOutcome.ACCEPTED
    assert d2.correlation_id == d1.correlation_id
    assert d2.outcome == d1.outcome


def test_head_unavailable_fails_closed():
    head, naming, token = _head_and_naming(21)
    naming.set_head_available(False)
    d = naming.publish(
        ServicePublicationRequest(
            service_name="svc.down", publisher_id="pub-1",
            endpoints=[_ep()], requested_at=15000.0, correlation_id="d1",
        ),
        token=token, now=15000.0,
    )
    assert d.outcome == PublicationOutcome.REJECTED
    assert d.reason_code == "head_unavailable"


def test_unreachable_endpoint_does_not_change_ownership():
    """Naming store does not observe reachability; identity stays stable."""
    head, naming, token = _head_and_naming(22)
    d = naming.publish(
        ServicePublicationRequest(
            service_name="svc.reach", publisher_id="pub-1",
            endpoints=[_ep("maybe-down")], requested_at=16000.0, correlation_id="u1",
        ),
        token=token, now=16000.0,
    )
    assert d.binding.owner_id == "pub-1"
    look = naming.lookup(
        ServiceBindingLookupRequest(service_name="svc.reach", requested_at=16001.0),
        now=16001.0,
    )
    assert look.found is True
    assert look.binding.owner_id == "pub-1"


# ---------------------------------------------------------------------------
# Regression: existing Octopie behaviour intact
# ---------------------------------------------------------------------------

def test_existing_admission_path_unaffected():
    head = Head(HeadConfig.for_target(4, seed=99))
    tokens = bootstrap_authorized(head, ["n0", "n1"])
    result = head.request_admission("n0", tokens["n0"], now=1.0)
    assert result.admitted is True
    assert head.admitted_count() == 1


def test_contract_version_unchanged():
    assert CONTRACT_VERSION == "octopie-aurora/1.0"


# ---------------------------------------------------------------------------
# Head integration: cascade revoke + availability
# ---------------------------------------------------------------------------

def test_head_attach_naming_cascades_on_revoke():
    head = Head(HeadConfig(seed=30))
    identity = make_simulated_identity(
        "pub-1", capabilities={CAPABILITY_PUBLISH_SERVICE, "worker"}
    )
    head.register_and_authorize(identity)
    token = head.issue_token("pub-1")
    naming = NamingService(head.identity)
    head.attach_naming(naming)

    d = naming.publish(
        ServicePublicationRequest(
            service_name="svc.head",
            publisher_id="pub-1",
            endpoints=[_ep()],
            requested_at=20000.0,
            correlation_id="h1",
        ),
        token=token,
        now=20000.0,
    )
    assert d.outcome == PublicationOutcome.ACCEPTED

    head.revoke("pub-1")
    look = naming.lookup(
        ServiceBindingLookupRequest(service_name="svc.head", requested_at=20001.0),
        now=20001.0,
    )
    assert look.found is False
    assert look.reason_code == "revoked"


def test_head_pause_blocks_naming_publish():
    head = Head(HeadConfig(seed=31))
    identity = make_simulated_identity(
        "pub-1", capabilities={CAPABILITY_PUBLISH_SERVICE}
    )
    head.register_and_authorize(identity)
    token = head.issue_token("pub-1")
    naming = NamingService(head.identity)
    head.attach_naming(naming)

    head.pause_admissions(reason="maintenance")
    d = naming.publish(
        ServicePublicationRequest(
            service_name="svc.paused",
            publisher_id="pub-1",
            endpoints=[_ep()],
            requested_at=21000.0,
            correlation_id="p1",
        ),
        token=token,
        now=21000.0,
    )
    assert d.outcome == PublicationOutcome.REJECTED
    assert d.reason_code == "head_unavailable"

    head.resume_admissions()
    d2 = naming.publish(
        ServicePublicationRequest(
            service_name="svc.paused",
            publisher_id="pub-1",
            endpoints=[_ep()],
            requested_at=21001.0,
            correlation_id="p2",
        ),
        token=token,
        now=21001.0,
    )
    assert d2.outcome == PublicationOutcome.ACCEPTED
