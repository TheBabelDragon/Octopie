"""Stable adapter interfaces for future ecosystem integration.

These interfaces are intentionally minimal and independently testable.
They do NOT import Aurora, REA, or CANtheon code. Concrete adapters
must be supplied by the integrator and validated against their own
contracts before use.

Design rules:
- No mandatory dependencies on external projects.
- Adapters are optional; Octopie core runs without them.
- Data flows inbound as structured observations only.
- Adapters never grant authorization or admission.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class NetworkHealthObservation:
    source: str
    timestamp: float
    path_id: str
    latency_ms: Optional[float] = None
    packet_loss: Optional[float] = None
    reachable: bool = True
    detail: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProtocolEvidence:
    source: str
    timestamp: float
    evidence_id: str
    protocol: str
    summary: str
    confidence: float = 0.0
    detail: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StructuredObservation:
    source: str
    timestamp: float
    observation_id: str
    category: str
    payload: Dict[str, Any] = field(default_factory=dict)


class NetworkHealthAdapter(ABC):
    @abstractmethod
    def poll(self) -> List[NetworkHealthObservation]:
        ...

    @abstractmethod
    def name(self) -> str:
        ...


class ProtocolEvidenceAdapter(ABC):
    @abstractmethod
    def poll(self) -> List[ProtocolEvidence]:
        ...

    @abstractmethod
    def name(self) -> str:
        ...


class ObservationAdapter(ABC):
    @abstractmethod
    def poll(self) -> List[StructuredObservation]:
        ...

    @abstractmethod
    def name(self) -> str:
        ...


class NullNetworkHealthAdapter(NetworkHealthAdapter):
    def poll(self) -> List[NetworkHealthObservation]:
        return []

    def name(self) -> str:
        return "null-network-health"


class NullProtocolEvidenceAdapter(ProtocolEvidenceAdapter):
    def poll(self) -> List[ProtocolEvidence]:
        return []

    def name(self) -> str:
        return "null-protocol-evidence"


class NullObservationAdapter(ObservationAdapter):
    def poll(self) -> List[StructuredObservation]:
        return []

    def name(self) -> str:
        return "null-observation"


@dataclass
class AdapterRegistry:
    network_health: NetworkHealthAdapter = field(default_factory=NullNetworkHealthAdapter)
    protocol_evidence: ProtocolEvidenceAdapter = field(default_factory=NullProtocolEvidenceAdapter)
    observation: ObservationAdapter = field(default_factory=NullObservationAdapter)

    def collect_all(self) -> Dict[str, List[Any]]:
        return {
            "network_health": self.network_health.poll(),
            "protocol_evidence": self.protocol_evidence.poll(),
            "observation": self.observation.poll(),
        }
