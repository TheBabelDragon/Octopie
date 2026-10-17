"""Admission control: explicit authorization, capability checks, capacity, protocol.

Any failed check prevents admission. Rejection reasons are recorded without
exposing secrets.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, TYPE_CHECKING

from .identity import CredentialStatus, IdentityStore
from .topology import NodeState, Topology

if TYPE_CHECKING:
    from .config import HeadConfig
    from .limits import RateLimiter


class RejectionReason(Enum):
    UNAUTHENTICATED = "unauthenticated"
    UNAUTHORIZED = "unauthorized"
    REVOKED = "revoked"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    RATE_LIMITED = "rate_limited"
    PROTOCOL_INCOMPATIBLE = "protocol_incompatible"
    DUPLICATE_IDENTITY = "duplicate_identity"
    REPLAY_DETECTED = "replay_detected"
    HEAD_UNAVAILABLE = "head_unavailable"
    POLICY_ERROR = "policy_error"
    INVALID_CREDENTIAL = "invalid_credential"
    ALREADY_ADMITTED = "already_admitted"


@dataclass(frozen=True)
class AdmissionResult:
    admitted: bool
    node_id: str
    reason: Optional[RejectionReason] = None
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.admitted


class AdmissionController:
    """Policy-bounded admission gate."""

    SUPPORTED_PROTOCOL = "octopie/1"

    def __init__(
        self,
        identity: IdentityStore,
        topology: Topology,
        config: "HeadConfig",
        rate_limiter: "RateLimiter",
    ):
        self._identity = identity
        self._topology = topology
        self._config = config
        self._rate_limiter = rate_limiter
        self._head_available = True

    def set_head_available(self, available: bool) -> None:
        self._head_available = available

    def admit(
        self,
        node_id: str,
        token: str,
        protocol: str = "octopie/1",
        nonce: Optional[str] = None,
        now: Optional[float] = None,
    ) -> AdmissionResult:
        """Attempt to admit a node. Fail closed on any check failure."""

        # 0. Head availability
        if not self._head_available:
            return self._reject(node_id, RejectionReason.HEAD_UNAVAILABLE, "head control plane unavailable")

        # 1. Protocol compatibility
        if protocol != self.SUPPORTED_PROTOCOL:
            return self._reject(node_id, RejectionReason.PROTOCOL_INCOMPATIBLE, f"unsupported protocol {protocol}")

        # 2. Identity exists
        identity = self._identity.get_identity(node_id)
        if identity is None:
            return self._reject(node_id, RejectionReason.UNAUTHENTICATED, "unknown identity")

        # 3. Revocation check
        if self._identity.is_revoked(node_id):
            self._topology.transition(node_id, NodeState.REVOKED, "revoked")
            return self._reject(node_id, RejectionReason.REVOKED, "node revoked")

        # 4. Credential verification
        status = self._identity.verify_credential(node_id, token, nonce=nonce, now=now)
        if status == CredentialStatus.REVOKED:
            return self._reject(node_id, RejectionReason.REVOKED, "credential revoked")
        if status == CredentialStatus.EXPIRED:
            return self._reject(node_id, RejectionReason.INVALID_CREDENTIAL, "credential expired")
        if status == CredentialStatus.UNKNOWN:
            if nonce is not None:
                return self._reject(node_id, RejectionReason.REPLAY_DETECTED, "nonce replay or invalid token")
            return self._reject(node_id, RejectionReason.INVALID_CREDENTIAL, "invalid credential")

        # 5. Explicit authorization (never inferred from discovery or peer trust)
        if self._config.require_explicit_authorization and not self._identity.is_authorized(node_id):
            return self._reject(node_id, RejectionReason.UNAUTHORIZED, "not explicitly authorized")

        # 6. Already admitted?
        rec = self._topology.get(node_id)
        if rec is not None and rec.state == NodeState.ADMITTED:
            return self._reject(node_id, RejectionReason.ALREADY_ADMITTED, "already admitted")

        # 7. Capacity
        admitted_count = self._topology.count_in_state(NodeState.ADMITTED)
        if admitted_count >= self._config.limits.max_nodes:
            return self._reject(node_id, RejectionReason.CAPACITY_EXCEEDED, "node capacity reached")

        # 8. Rate limit
        if not self._rate_limiter.allow_admission(now=now):
            return self._reject(node_id, RejectionReason.RATE_LIMITED, "expansion rate limit")

        # 9. Ensure topology record exists and advance states
        if rec is None:
            rec = self._topology.add_discovered(node_id)
        self._topology.transition(node_id, NodeState.AUTHENTICATED)
        self._topology.transition(node_id, NodeState.AUTHORIZED)
        ok = self._topology.transition(node_id, NodeState.ADMITTED)
        if not ok:
            return self._reject(node_id, RejectionReason.POLICY_ERROR, "state transition failed")

        rec.capabilities = identity.capabilities
        self._rate_limiter.record_admission(now=now)

        return AdmissionResult(admitted=True, node_id=node_id, message="admitted")

    def _reject(self, node_id: str, reason: RejectionReason, message: str) -> AdmissionResult:
        rec = self._topology.get(node_id)
        if rec is not None:
            rec.rejection_reason = reason.value
        return AdmissionResult(admitted=False, node_id=node_id, reason=reason, message=message)
