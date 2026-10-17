"""Bridge between Octopie Head and the Aurora integration contract.

FakeAuroraAdapter: deterministic stand-in for Aurora observations (tests).
DecisionService: produces AdmissionDecision / MembershipSnapshot / NodeRevocation
from Head state without importing Aurora code.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Set

from .contract import (
    AdmissionDecision, AdmissionRequested, CapabilityDecision, CoordinationStatus,
    DecisionOutcome, MembershipSnapshot, NodeHealthObserved, NodeObserved,
    NodeRevocation, TrustOutcome,
)
from .head import Head
from .identity import make_simulated_identity
from .topology import NodeState


class FakeAuroraAdapter:
    def __init__(self, seed: int = 42):
        self.seed = seed
        self._observed: Dict[str, NodeObserved] = {}
        self._health: Dict[str, NodeHealthObserved] = {}
        self._t = 1_000_000.0

    def observe_node(self, node_id: str, reachable: bool = True, latency_ms: float = 5.0) -> NodeObserved:
        self._t += 1.0
        obs = NodeObserved(
            node_id=node_id, observed_at=self._t, source="fake-aurora",
            reachable=reachable, path_id=f"path-{node_id}", latency_ms=latency_ms,
        )
        self._observed[node_id] = obs
        return obs

    def report_health(self, node_id: str, healthy: bool, detail: str = "") -> NodeHealthObserved:
        self._t += 0.5
        h = NodeHealthObserved(node_id=node_id, observed_at=self._t, healthy=healthy, detail=detail)
        self._health[node_id] = h
        return h

    def poll_observations(self) -> List[NodeObserved]:
        return list(self._observed.values())

    def poll_health(self) -> List[NodeHealthObserved]:
        return list(self._health.values())

    def name(self) -> str:
        return "fake-aurora"


class DecisionService:
    def __init__(self, head: Head, decision_ttl_seconds: float = 300.0):
        self.head = head
        self.decision_ttl = decision_ttl_seconds
        self._seen_correlations: Set[str] = set()
        self._decisions: Dict[str, AdmissionDecision] = {}

    def ingest_observation(self, obs: NodeObserved) -> TrustOutcome:
        if self.head.topology.get(obs.node_id) is None:
            self.head.topology.add_discovered(obs.node_id)
        return TrustOutcome.OBSERVED_UNVERIFIED

    def handle_admission_request(
        self, req: AdmissionRequested, token: Optional[str] = None, now: Optional[float] = None,
    ) -> AdmissionDecision:
        now = now if now is not None else time.time()
        if req.correlation_id in self._seen_correlations:
            existing = self._decisions.get(req.node_id)
            if existing is not None:
                return existing
        self._seen_correlations.add(req.correlation_id)
        if not token:
            decision = AdmissionDecision(
                node_id=req.node_id, outcome=DecisionOutcome.REJECT,
                trust_outcome=TrustOutcome.OBSERVED_UNVERIFIED, reason_code="missing_credential",
                decided_at=now, policy_version=self.head.config.audit.policy_version,
                correlation_id=req.correlation_id, expires_at=now + self.decision_ttl,
            )
            self._decisions[req.node_id] = decision
            return decision
        result = self.head.request_admission(req.node_id, token, protocol=req.protocol, now=now)
        if result.admitted:
            trust, outcome, reason = TrustOutcome.ADMITTED_ACTIVE, DecisionOutcome.ADMIT, "admitted"
            caps = list(self.head.topology.get(req.node_id).capabilities if self.head.topology.get(req.node_id) else [])
        else:
            outcome, reason = DecisionOutcome.REJECT, (result.reason.value if result.reason else result.message)
            rec = self.head.topology.get(req.node_id)
            if rec and rec.state == NodeState.REVOKED:
                trust = TrustOutcome.REVOKED
            elif self.head.identity.get_identity(req.node_id) is None:
                trust = TrustOutcome.OBSERVED_UNVERIFIED
            elif not self.head.identity.is_authorized(req.node_id):
                trust = TrustOutcome.AUTHENTICATED_NOT_AUTHORIZED
            else:
                trust = TrustOutcome.AUTHORIZED_NOT_ADMITTED
            caps = []
        decision = AdmissionDecision(
            node_id=req.node_id, outcome=outcome, trust_outcome=trust, reason_code=reason,
            decided_at=now, policy_version=self.head.config.audit.policy_version,
            correlation_id=req.correlation_id, expires_at=now + self.decision_ttl, capabilities=caps,
        )
        self._decisions[req.node_id] = decision
        return decision

    def membership_snapshot(self, now: Optional[float] = None) -> MembershipSnapshot:
        now = now if now is not None else time.time()
        return MembershipSnapshot(
            snapshot_at=now, admitted_node_ids=sorted(self.head.topology.admitted_nodes().keys()),
            policy_version=self.head.config.audit.policy_version,
        )

    def revoke(self, node_id: str, reason: str = "revoked", now: Optional[float] = None) -> NodeRevocation:
        now = now if now is not None else time.time()
        self.head.revoke(node_id)
        self._decisions.pop(node_id, None)
        return NodeRevocation(
            node_id=node_id, revoked_at=now, reason_code=reason,
            policy_version=self.head.config.audit.policy_version,
        )

    def capability_decision(self, node_id: str, capability: str, now: Optional[float] = None) -> CapabilityDecision:
        now = now if now is not None else time.time()
        rec = self.head.topology.get(node_id)
        granted = rec is not None and rec.state == NodeState.ADMITTED and capability in rec.capabilities
        return CapabilityDecision(
            node_id=node_id, capability=capability, granted=granted,
            reason_code="granted" if granted else "denied", decided_at=now,
            policy_version=self.head.config.audit.policy_version,
        )

    def status(self, now: Optional[float] = None) -> CoordinationStatus:
        now = now if now is not None else time.time()
        return CoordinationStatus(
            reported_at=now, octopie_available=self.head.is_available, aurora_observe_only=True,
            admissions_paused=not self.head.is_available, admitted_count=self.head.admitted_count(),
            target_nodes=self.head.config.target_nodes,
            detail="simulation" if not self.head.config.network_expansion_enabled else "live-policy",
        )


def bootstrap_authorized(head: Head, node_ids: List[str]) -> Dict[str, str]:
    tokens = {}
    for nid in node_ids:
        head.register_and_authorize(make_simulated_identity(nid))
        tokens[nid] = head.issue_token(nid)
    return tokens
