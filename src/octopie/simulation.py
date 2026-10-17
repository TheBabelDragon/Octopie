"""Deterministic network growth, admission, failures, revocation, and recovery
without requiring real external peers.

Uses a fixed seed for reproducible runs. Emits a structured SimulationSummary.
"""

from __future__ import annotations

import random
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .config import HeadConfig
from .diagnostics import diagnose
from .events import EventLog, EventType
from .expansion import ExpansionEngine, ExpansionRequest
from .head import Head
from .identity import make_simulated_identity
from .topology import NodeState


@dataclass
class SimulationSummary:
    seed: int
    target: int
    admitted: int
    authorized: int
    rejected_count: int
    rejection_reasons: Dict[str, int] = field(default_factory=dict)
    failure_events: int = 0
    recovery_outcomes: List[str] = field(default_factory=list)
    resource_limit_events: int = 0
    config_snapshot: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NetworkSimulator:
    def __init__(self, config: Optional[HeadConfig] = None):
        self.config = config or HeadConfig(seed=42)
        if self.config.seed is None:
            object.__setattr__(self.config, "seed", 42)
        self.head = Head(self.config)
        self.rng = random.Random(self.config.seed)
        self._tokens: dict[str, str] = {}
        self._node_ids: List[str] = []
        self.event_log = EventLog(
            hash_link=self.config.audit.hash_link,
            policy_version=self.config.audit.policy_version,
        )
        self.expansion = ExpansionEngine(self.head, self.event_log)

    def bootstrap_identities(self, count: Optional[int] = None) -> List[str]:
        n = count if count is not None else self.config.target_nodes
        ids = []
        for i in range(n):
            node_id = f"node-{i:04d}"
            identity = make_simulated_identity(node_id)
            self.head.register_and_authorize(identity)
            token = self.head.issue_token(node_id)
            self._tokens[node_id] = token
            ids.append(node_id)
            self.event_log.emit(EventType.NODE_DISCOVERED, outcome="info", node_id=node_id)
        self._node_ids = ids
        return ids

    def grow_to_target(self, target: Optional[int] = None) -> int:
        target = target if target is not None else self.config.target_nodes
        if not self._node_ids:
            self.bootstrap_identities(max(target, self.config.target_nodes))
        requests = [
            ExpansionRequest(node_id=nid, token=self._tokens[nid], request_id=f"req-{nid}")
            for nid in self._node_ids[:target]
        ]
        outcomes = self.expansion.expand_batch(requests, stop_on_limit=False)
        return sum(1 for o in outcomes if o.admitted)

    def inject_unauthenticated(self) -> bool:
        result = self.head.request_admission("ghost-9999", "fake-token")
        return not result.admitted

    def inject_unauthorized(self) -> bool:
        node_id = "unauth-0001"
        identity = make_simulated_identity(node_id)
        self.head.identity.register_identity(identity)
        try:
            token = self.head.identity.issue_credential(node_id)
        except ValueError:
            token = "dummy"
        result = self.head.request_admission(node_id, token)
        return not result.admitted and result.reason is not None

    def revoke_and_verify(self, node_id: str) -> bool:
        self.head.revoke(node_id)
        self.event_log.emit(EventType.NODE_REVOKED, outcome="success", node_id=node_id)
        rec = self.head.topology.get(node_id)
        if rec is None or rec.state != NodeState.REVOKED:
            return False
        token = self._tokens.get(node_id, "stale")
        result = self.head.request_admission(node_id, token)
        return not result.admitted

    def peer_cannot_confer_trust(self) -> bool:
        outsider = "peer-pushed-0001"
        identity = make_simulated_identity(outsider)
        self.head.identity.register_identity(identity)
        try:
            self.head.identity.issue_credential(outsider)
            return False
        except ValueError:
            pass
        result = self.head.request_admission(outsider, "any")
        return not result.admitted

    def run_failure_and_recovery(self, node_id: str) -> bool:
        before = self.head.admitted_count()
        self.head.health.report_failure(node_id, detail="simulated crash")
        self.event_log.emit(EventType.HEALTH_DEGRADED, outcome="failure", node_id=node_id)
        for _ in range(self.config.limits.recovery_max_attempts + 2):
            self.head.health.report_failure(node_id, detail="retry")
        rec = self.head.topology.get(node_id)
        after = self.head.admitted_count()
        return after <= before and rec is not None and rec.state in (
            NodeState.ISOLATED, NodeState.DEGRADED, NodeState.REVOKED
        )

    def head_loss_pauses_admissions(self) -> bool:
        self.head.simulate_head_loss()
        self.event_log.emit(EventType.HEAD_SAFE_ENTERED, outcome="info", reason_code="head_loss")
        spare = f"spare-{self.rng.randint(10000, 99999)}"
        identity = make_simulated_identity(spare)
        self.head.register_and_authorize(identity)
        token = self.head.issue_token(spare)
        result = self.head.request_admission(spare, token)
        paused_ok = not result.admitted
        self.head.recover_from_head_loss()
        self.event_log.emit(EventType.HEAD_SAFE_EXITED, outcome="info")
        return paused_ok

    def run_full_scenario(self, target: Optional[int] = None) -> SimulationSummary:
        t0 = time.time()
        target = target if target is not None else self.config.target_nodes
        self.bootstrap_identities(max(target, 8))
        self.grow_to_target(target)
        rejection_reasons: Dict[str, int] = {}
        for o in self.expansion.outcomes():
            if not o.admitted and o.reason:
                rejection_reasons[o.reason] = rejection_reasons.get(o.reason, 0) + 1
        recovery_outcomes: List[str] = []
        if self._node_ids and self.head.admitted_count() > 0:
            victim = self._node_ids[0]
            if self.head.topology.get(victim) and self.head.topology.get(victim).state == NodeState.ADMITTED:
                ok = self.run_failure_and_recovery(victim)
                recovery_outcomes.append("bounded" if ok else "unexpected")
        diag = diagnose(self.head)
        return SimulationSummary(
            seed=self.config.seed or 42,
            target=target,
            admitted=self.head.admitted_count(),
            authorized=len(self.head.identity.list_authorized()),
            rejected_count=sum(rejection_reasons.values()),
            rejection_reasons=rejection_reasons,
            failure_events=len(self.event_log.by_type(EventType.HEALTH_DEGRADED)),
            recovery_outcomes=recovery_outcomes,
            resource_limit_events=len(self.event_log.by_type(EventType.EXPANSION_LIMITED)),
            config_snapshot={
                "head_id": self.config.head_id,
                "max_nodes": self.config.limits.max_nodes,
                "target_nodes": self.config.target_nodes,
                "network_expansion_enabled": self.config.network_expansion_enabled,
            },
            duration_seconds=time.time() - t0,
            notes=diag.messages,
        )
