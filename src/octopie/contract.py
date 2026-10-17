"""Octopie ↔ Aurora integration contract (versioned).

Contract version: octopie-aurora/1.0

Authority:
  Aurora owns network reachability, routes, transport outcomes, artifact history.
  Octopie owns trusted membership, admission, authorization, resource budgets.

Messages never carry private keys, bearer tokens, or reusable credentials.
Transport success is never interpreted as admission.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

CONTRACT_VERSION = "octopie-aurora/1.0"
SUPPORTED_VERSIONS = frozenset({CONTRACT_VERSION})


class TrustOutcome(str, Enum):
    OBSERVED_UNVERIFIED = "observed_unverified"
    AUTHENTICATED_NOT_AUTHORIZED = "authenticated_not_authorized"
    AUTHORIZED_NOT_ADMITTED = "authorized_not_admitted"
    ADMITTED_ACTIVE = "admitted_active"
    DEGRADED = "degraded"
    ISOLATED = "isolated"
    REVOKED = "revoked"
    REJECTED = "rejected"


class DecisionOutcome(str, Enum):
    ADMIT = "admit"
    REJECT = "reject"
    DEFER = "defer"
    REVOKE = "revoke"


@dataclass
class ContractError(Exception):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def _require_version(version: str) -> None:
    if version not in SUPPORTED_VERSIONS:
        raise ContractError(
            "incompatible_contract_version",
            f"got {version!r}, supported={sorted(SUPPORTED_VERSIONS)}",
        )


@dataclass(frozen=True)
class NodeObserved:
    node_id: str
    observed_at: float
    source: str = "aurora"
    reachable: bool = True
    path_id: Optional[str] = None
    latency_ms: Optional[float] = None
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    contract_version: str = CONTRACT_VERSION
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NodeObserved":
        _require_version(d.get("contract_version", ""))
        return cls(
            node_id=str(d["node_id"]),
            observed_at=float(d["observed_at"]),
            source=str(d.get("source", "aurora")),
            reachable=bool(d.get("reachable", True)),
            path_id=d.get("path_id"),
            latency_ms=d.get("latency_ms"),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
            contract_version=str(d["contract_version"]),
            detail=dict(d.get("detail") or {}),
        )


@dataclass(frozen=True)
class AdmissionRequested:
    node_id: str
    requested_at: float
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    protocol: str = "octopie/1"
    capabilities_requested: List[str] = field(default_factory=list)
    contract_version: str = CONTRACT_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AdmissionRequested":
        _require_version(d.get("contract_version", ""))
        return cls(
            node_id=str(d["node_id"]),
            requested_at=float(d["requested_at"]),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
            protocol=str(d.get("protocol", "octopie/1")),
            capabilities_requested=list(d.get("capabilities_requested") or []),
            contract_version=str(d["contract_version"]),
        )


@dataclass(frozen=True)
class AdmissionDecision:
    node_id: str
    outcome: DecisionOutcome
    trust_outcome: TrustOutcome
    reason_code: str
    decided_at: float
    policy_version: str
    contract_version: str = CONTRACT_VERSION
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    expires_at: Optional[float] = None
    capabilities: List[str] = field(default_factory=list)

    def is_expired(self, now: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        return (now if now is not None else time.time()) >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        d["trust_outcome"] = self.trust_outcome.value
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AdmissionDecision":
        _require_version(d.get("contract_version", ""))
        return cls(
            node_id=str(d["node_id"]),
            outcome=DecisionOutcome(d["outcome"]),
            trust_outcome=TrustOutcome(d["trust_outcome"]),
            reason_code=str(d.get("reason_code", "")),
            decided_at=float(d["decided_at"]),
            policy_version=str(d.get("policy_version", "1")),
            contract_version=str(d["contract_version"]),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
            expires_at=float(d["expires_at"]) if d.get("expires_at") is not None else None,
            capabilities=list(d.get("capabilities") or []),
        )


@dataclass(frozen=True)
class MembershipSnapshot:
    snapshot_at: float
    admitted_node_ids: List[str]
    policy_version: str
    contract_version: str = CONTRACT_VERSION
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "MembershipSnapshot":
        _require_version(d.get("contract_version", ""))
        return cls(
            snapshot_at=float(d["snapshot_at"]),
            admitted_node_ids=list(d.get("admitted_node_ids") or []),
            policy_version=str(d.get("policy_version", "1")),
            contract_version=str(d["contract_version"]),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
        )


@dataclass(frozen=True)
class CapabilityDecision:
    node_id: str
    capability: str
    granted: bool
    reason_code: str
    decided_at: float
    policy_version: str
    contract_version: str = CONTRACT_VERSION
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CapabilityDecision":
        _require_version(d.get("contract_version", ""))
        return cls(
            node_id=str(d["node_id"]),
            capability=str(d["capability"]),
            granted=bool(d["granted"]),
            reason_code=str(d.get("reason_code", "")),
            decided_at=float(d["decided_at"]),
            policy_version=str(d.get("policy_version", "1")),
            contract_version=str(d["contract_version"]),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
        )


@dataclass(frozen=True)
class NodeHealthObserved:
    node_id: str
    observed_at: float
    healthy: bool
    detail: str = ""
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    contract_version: str = CONTRACT_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NodeHealthObserved":
        _require_version(d.get("contract_version", ""))
        return cls(
            node_id=str(d["node_id"]),
            observed_at=float(d["observed_at"]),
            healthy=bool(d["healthy"]),
            detail=str(d.get("detail", "")),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
            contract_version=str(d["contract_version"]),
        )


@dataclass(frozen=True)
class NodeRevocation:
    node_id: str
    revoked_at: float
    reason_code: str
    policy_version: str
    contract_version: str = CONTRACT_VERSION
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NodeRevocation":
        _require_version(d.get("contract_version", ""))
        return cls(
            node_id=str(d["node_id"]),
            revoked_at=float(d["revoked_at"]),
            reason_code=str(d.get("reason_code", "")),
            policy_version=str(d.get("policy_version", "1")),
            contract_version=str(d["contract_version"]),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
        )


@dataclass(frozen=True)
class CoordinationStatus:
    reported_at: float
    octopie_available: bool
    aurora_observe_only: bool
    admissions_paused: bool
    admitted_count: int
    target_nodes: int
    contract_version: str = CONTRACT_VERSION
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CoordinationStatus":
        _require_version(d.get("contract_version", ""))
        return cls(
            reported_at=float(d["reported_at"]),
            octopie_available=bool(d["octopie_available"]),
            aurora_observe_only=bool(d.get("aurora_observe_only", True)),
            admissions_paused=bool(d.get("admissions_paused", False)),
            admitted_count=int(d.get("admitted_count", 0)),
            target_nodes=int(d.get("target_nodes", 42)),
            contract_version=str(d["contract_version"]),
            detail=str(d.get("detail", "")),
        )


def serialize(obj: Any) -> str:
    if hasattr(obj, "to_dict"):
        return json.dumps(obj.to_dict(), sort_keys=True, separators=(",", ":"))
    raise TypeError(f"not a contract message: {type(obj)}")


def parse_decision(raw: str | Dict[str, Any]) -> AdmissionDecision:
    data = json.loads(raw) if isinstance(raw, str) else raw
    return AdmissionDecision.from_dict(data)
