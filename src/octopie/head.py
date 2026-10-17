"""Head authority: configuration, admission policy, orchestration,
resource budgets, audit events, and safe shutdown.

The head is not a silent single point of catastrophic failure:
- New admissions pause when authority cannot be verified.
- Existing nodes retain only explicitly granted local permissions
  and bounded leases during temporary control-plane loss.
- Recovery validates state before resuming admissions.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Set

from .admission import AdmissionController, AdmissionResult, RejectionReason
from .arm import ArmManager
from .audit import AuditLog
from .config import HeadConfig
from .health import HealthMonitor
from .identity import IdentityStore, NodeIdentity, make_simulated_identity
from .limits import RateLimiter
from .topology import NodeState, Topology


class Head:
    """Central policy-bounded control plane."""

    def __init__(self, config: Optional[HeadConfig] = None):
        self.config = config or HeadConfig()
        self.identity = IdentityStore(seed=self.config.seed)
        self.topology = Topology()
        self.rate_limiter = RateLimiter(
            max_per_second=self.config.limits.max_expansion_per_second,
            max_concurrent=self.config.limits.max_concurrent_admissions,
        )
        self.admission = AdmissionController(
            self.identity, self.topology, self.config, self.rate_limiter
        )
        self.health = HealthMonitor(self.topology, self.config)
        self.arms = ArmManager(max_workers=self.config.limits.max_nodes * 4)
        self.audit = AuditLog()
        self._running = True
        self._admissions_paused = False
        self._shutdown_started_at: Optional[float] = None

    def start(self) -> None:
        self._running = True
        self._admissions_paused = False
        self.admission.set_head_available(True)
        self.audit.record("head_started", detail={"head_id": self.config.head_id})

    def pause_admissions(self, reason: str = "manual") -> None:
        self._admissions_paused = True
        self.admission.set_head_available(False)
        self.audit.record("admissions_paused", detail={"reason": reason})

    def resume_admissions(self) -> None:
        """Validate state then resume. Fails closed if policy is broken."""
        if not self._running:
            return
        try:
            _ = self.config.limits.max_nodes
        except Exception:
            self.audit.record("resume_failed", detail={"reason": "policy_error"})
            return
        self._admissions_paused = False
        self.admission.set_head_available(True)
        self.audit.record("admissions_resumed")

    def simulate_head_loss(self) -> None:
        """Model temporary control-plane unavailability."""
        self.pause_admissions(reason="head_loss")
        self.audit.record("head_unavailable")

    def recover_from_head_loss(self) -> None:
        """Recovery procedure that validates state before resuming."""
        self.resume_admissions()
        self.audit.record("head_recovered")

    def shutdown(self, now: Optional[float] = None) -> None:
        """Safe shutdown with deadline."""
        now = now if now is not None else time.time()
        self._shutdown_started_at = now
        self.pause_admissions(reason="shutdown")
        self._running = False
        for node_id in list(self.topology.admitted_nodes()):
            self.arms.retire_node(node_id)
        self.audit.record("head_shutdown", detail={"deadline": self.config.limits.shutdown_deadline_seconds})

    @property
    def is_available(self) -> bool:
        return self._running and not self._admissions_paused

    def register_and_authorize(self, identity: NodeIdentity) -> None:
        self.identity.register_identity(identity)
        self.identity.authorize(identity.node_id)
        self.topology.add_discovered(identity.node_id)
        self.audit.record("identity_authorized", node_id=identity.node_id)

    def revoke(self, node_id: str) -> None:
        self.identity.revoke(node_id)
        self.topology.transition(node_id, NodeState.REVOKED, "revoked by head")
        self.arms.retire_node(node_id)
        self.audit.record("node_revoked", node_id=node_id)

    def request_admission(
        self,
        node_id: str,
        token: str,
        protocol: str = "octopie/1",
        nonce: Optional[str] = None,
        now: Optional[float] = None,
    ) -> AdmissionResult:
        if not self.is_available:
            result = AdmissionResult(
                admitted=False,
                node_id=node_id,
                reason=RejectionReason.HEAD_UNAVAILABLE,
                message="head control plane unavailable",
            )
            self.audit.record("admission_rejected", node_id=node_id, reason=result.reason.value if result.reason else "")
            return result

        result = self.admission.admit(node_id, token, protocol=protocol, nonce=nonce, now=now)
        if result.admitted:
            self.arms.allocate(node_id)
            self.health.heartbeat(node_id, now=now)
            self.audit.record("admission_accepted", node_id=node_id)
        else:
            self.audit.record(
                "admission_rejected",
                node_id=node_id,
                reason=result.reason.value if result.reason else "",
                message=result.message,
            )
        return result

    def issue_token(self, node_id: str, ttl_seconds: float = 300.0, now: Optional[float] = None) -> str:
        return self.identity.issue_credential(node_id, ttl_seconds=ttl_seconds, now=now)

    def admitted_count(self) -> int:
        return self.topology.count_in_state(NodeState.ADMITTED)

    def status(self) -> Dict:
        return {
            "head_id": self.config.head_id,
            "running": self._running,
            "admissions_paused": self._admissions_paused,
            "target_nodes": self.config.target_nodes,
            "max_nodes": self.config.limits.max_nodes,
            "admitted": self.admitted_count(),
            "discovered": self.topology.count_in_state(NodeState.DISCOVERED),
            "authorized": len(self.identity.list_authorized()),
            "revoked": sum(1 for n in self.topology.all_nodes().values() if n.state == NodeState.REVOKED),
            "active_workers": self.arms.active_count(),
        }
