"""Health monitoring and bounded recovery.

Failure of one worker triggers bounded recovery without exceeding
configured limits. Recovery loops cannot create uncontrolled growth.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TYPE_CHECKING

from .topology import NodeState, Topology

if TYPE_CHECKING:
    from .config import HeadConfig


@dataclass
class HealthEvent:
    node_id: str
    event_type: str  # timeout | failure | recovered | isolated
    timestamp: float
    detail: str = ""


class HealthMonitor:
    """Detect timeouts/failures and perform bounded recovery."""

    def __init__(self, topology: Topology, config: "HeadConfig"):
        self._topology = topology
        self._config = config
        self._last_heartbeat: Dict[str, float] = {}
        self._events: List[HealthEvent] = []
        self._timeout_seconds = 15.0

    def heartbeat(self, node_id: str, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        self._last_heartbeat[node_id] = now
        rec = self._topology.get(node_id)
        if rec is not None and rec.state == NodeState.DEGRADED:
            # Successful heartbeat can restore from DEGRADED
            if rec.recovery_attempts <= self._config.limits.recovery_max_attempts:
                self._topology.transition(node_id, NodeState.ADMITTED)
                rec.recovery_attempts = 0
                self._events.append(HealthEvent(node_id, "recovered", now))

    def check_timeouts(self, now: Optional[float] = None) -> List[str]:
        """Mark timed-out nodes as DEGRADED. Returns list of affected node_ids."""
        now = now if now is not None else time.time()
        affected: List[str] = []
        for node_id, last in list(self._last_heartbeat.items()):
            if now - last > self._timeout_seconds:
                rec = self._topology.get(node_id)
                if rec is not None and rec.state == NodeState.ADMITTED:
                    self._topology.transition(node_id, NodeState.DEGRADED)
                    rec.recovery_attempts += 1
                    self._events.append(HealthEvent(node_id, "timeout", now, f"no heartbeat for {now - last:.1f}s"))
                    affected.append(node_id)
                    if rec.recovery_attempts > self._config.limits.recovery_max_attempts:
                        self._topology.transition(node_id, NodeState.ISOLATED, "recovery attempts exhausted")
                        self._events.append(HealthEvent(node_id, "isolated", now, "max recovery attempts exceeded"))
        return affected

    def report_failure(self, node_id: str, detail: str = "", now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        rec = self._topology.get(node_id)
        if rec is None:
            return
        if rec.state == NodeState.ADMITTED:
            self._topology.transition(node_id, NodeState.DEGRADED)
        rec.recovery_attempts += 1
        self._events.append(HealthEvent(node_id, "failure", now, detail))
        if rec.recovery_attempts > self._config.limits.recovery_max_attempts:
            self._topology.transition(node_id, NodeState.ISOLATED, "recovery attempts exhausted")
            self._events.append(HealthEvent(node_id, "isolated", now, "max recovery attempts exceeded"))

    def events(self) -> List[HealthEvent]:
        return list(self._events)
