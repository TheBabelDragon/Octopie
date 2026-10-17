"""Structured event contract for Octopie operations.

Every meaningful operation emits an event with a unique ID, type,
timestamp, outcome, reason code, and optional policy version.
Sensitive material is never included.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class EventType(str, Enum):
    NODE_DISCOVERED = "node_discovered"
    AUTH_SUCCEEDED = "auth_succeeded"
    AUTH_FAILED = "auth_failed"
    ADMISSION_AUTHORIZED = "admission_authorized"
    ADMISSION_REJECTED = "admission_rejected"
    NODE_ADMITTED = "node_admitted"
    CAPABILITY_GRANTED = "capability_granted"
    CAPABILITY_DENIED = "capability_denied"
    HEALTH_DEGRADED = "health_degraded"
    HEALTH_RECOVERED = "health_recovered"
    NODE_ISOLATED = "node_isolated"
    NODE_REVOKED = "node_revoked"
    EXPANSION_ATTEMPTED = "expansion_attempted"
    EXPANSION_LIMITED = "expansion_limited"
    EXPANSION_COMPLETED = "expansion_completed"
    RECOVERY_STARTED = "recovery_started"
    RECOVERY_FAILED = "recovery_failed"
    RECOVERY_COMPLETED = "recovery_completed"
    HEAD_SAFE_ENTERED = "head_safe_entered"
    HEAD_SAFE_EXITED = "head_safe_exited"
    PERSISTENCE_SAVED = "persistence_saved"
    PERSISTENCE_LOADED = "persistence_loaded"
    PERSISTENCE_FAILED = "persistence_failed"


_SENSITIVE_KEYS = frozenset({
    "token", "secret", "key", "credential", "password",
    "private_key", "bearer", "hmac", "raw_token",
})


@dataclass
class Event:
    event_id: str
    event_type: EventType
    timestamp: float
    outcome: str
    reason_code: str = ""
    node_id: Optional[str] = None
    policy_version: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)
    prev_hash: Optional[str] = None

    def __post_init__(self) -> None:
        for k in list(self.detail.keys()):
            if k.lower() in _SENSITIVE_KEYS:
                self.detail[k] = "[REDACTED]"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d

    def content_hash(self) -> str:
        payload = (
            f"{self.event_id}|{self.event_type.value}|{self.timestamp}|"
            f"{self.outcome}|{self.reason_code}|{self.node_id or ''}|"
            f"{self.policy_version or ''}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class EventLog:
    """In-memory structured event log with optional hash linking.

    Hash linking provides tamper-evidence within a single process run.
    It does NOT claim external immutability or cryptographic authentication
    of the underlying storage medium.
    """

    def __init__(self, hash_link: bool = True, policy_version: str = "1"):
        self._events: List[Event] = []
        self._hash_link = hash_link
        self._policy_version = policy_version
        self._last_hash: Optional[str] = None

    def emit(
        self,
        event_type: EventType,
        outcome: str = "info",
        reason_code: str = "",
        node_id: Optional[str] = None,
        **detail: Any,
    ) -> Event:
        ev = Event(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=time.time(),
            outcome=outcome,
            reason_code=reason_code,
            node_id=node_id,
            policy_version=self._policy_version,
            detail={k: v for k, v in detail.items() if k.lower() not in _SENSITIVE_KEYS},
            prev_hash=self._last_hash if self._hash_link else None,
        )
        if self._hash_link:
            self._last_hash = ev.content_hash()
        self._events.append(ev)
        return ev

    def events(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._events]

    def verify_chain(self) -> bool:
        if not self._hash_link:
            return True
        prev: Optional[str] = None
        for e in self._events:
            if e.prev_hash != prev:
                return False
            prev = e.content_hash()
        return True

    def by_type(self, event_type: EventType) -> List[Event]:
        return [e for e in self._events if e.event_type == event_type]

    def clear(self) -> None:
        self._events.clear()
        self._last_hash = None
