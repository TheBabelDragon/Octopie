"""Audit events. Sensitive material is redacted."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AuditEvent:
    timestamp: float
    event_type: str
    node_id: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def redacted(self) -> Dict[str, Any]:
        """Return a log-safe representation (no tokens, keys, or secrets)."""
        safe = {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "node_id": self.node_id,
        }
        # Only copy non-sensitive keys
        for k, v in self.detail.items():
            if k.lower() in {"token", "secret", "key", "credential", "password"}:
                safe[k] = "[REDACTED]"
            else:
                safe[k] = v
        return safe


class AuditLog:
    def __init__(self) -> None:
        self._events: List[AuditEvent] = []

    def record(self, event_type: str, node_id: Optional[str] = None, **detail: Any) -> None:
        self._events.append(
            AuditEvent(timestamp=time.time(), event_type=event_type, node_id=node_id, detail=detail)
        )

    def events(self) -> List[Dict[str, Any]]:
        return [e.redacted() for e in self._events]

    def clear(self) -> None:
        self._events.clear()
