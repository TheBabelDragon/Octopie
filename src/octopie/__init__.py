"""Octopie — secure head architecture for policy-bounded trusted-node networks."""

__version__ = "0.1.0"

from .head import Head
from .config import HeadConfig, LimitsConfig
from .topology import NodeState, NodeRecord
from .identity import IdentityStore, NodeIdentity
from .admission import AdmissionResult, RejectionReason

__all__ = [
    "Head",
    "HeadConfig",
    "LimitsConfig",
    "NodeState",
    "NodeRecord",
    "IdentityStore",
    "NodeIdentity",
    "AdmissionResult",
    "RejectionReason",
    "__version__",
]
