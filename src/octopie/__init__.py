"""Octopie — secure head architecture for policy-bounded trusted-node networks."""

__version__ = "0.3.0"

from .head import Head
from .config import HeadConfig, LimitsConfig, SimulationConfig, AuditConfig
from .topology import NodeState, NodeRecord
from .identity import IdentityStore, NodeIdentity
from .admission import AdmissionResult, RejectionReason
from .diagnostics import DiagnosticReport, diagnose, explain_rejection
from .events import EventType, EventLog
from .expansion import ExpansionEngine, ExpansionRequest
from .persistence import Store, SCHEMA_VERSION
from .contract import (
    CONTRACT_VERSION,
    TrustOutcome,
    DecisionOutcome,
    NodeObserved,
    AdmissionRequested,
    AdmissionDecision,
    MembershipSnapshot,
    CapabilityDecision,
    NodeHealthObserved,
    NodeRevocation,
    CoordinationStatus,
)

__all__ = [
    "Head", "HeadConfig", "LimitsConfig", "SimulationConfig", "AuditConfig",
    "NodeState", "NodeRecord", "IdentityStore", "NodeIdentity",
    "AdmissionResult", "RejectionReason",
    "DiagnosticReport", "diagnose", "explain_rejection",
    "EventType", "EventLog", "ExpansionEngine", "ExpansionRequest",
    "Store", "SCHEMA_VERSION",
    "CONTRACT_VERSION", "TrustOutcome", "DecisionOutcome",
    "NodeObserved", "AdmissionRequested", "AdmissionDecision",
    "MembershipSnapshot", "CapabilityDecision", "NodeHealthObserved",
    "NodeRevocation", "CoordinationStatus",
    "__version__",
]
