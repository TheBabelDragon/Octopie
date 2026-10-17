"""Bounded expansion engine.

Lifecycle: DISCOVER → VERIFY IDENTITY → AUTHORIZE → CHECK CAPACITY → ADMIT → MONITOR → REASSESS
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, TYPE_CHECKING

from .admission import AdmissionResult, RejectionReason
from .events import EventLog, EventType
from .topology import NodeState

if TYPE_CHECKING:
    from .head import Head


class ExpansionPhase(Enum):
    IDLE = auto()
    DISCOVER = auto()
    VERIFY = auto()
    AUTHORIZE = auto()
    CHECK_CAPACITY = auto()
    ADMIT = auto()
    MONITOR = auto()
    REASSESS = auto()
    PAUSED = auto()
    CANCELLED = auto()


@dataclass
class ExpansionRequest:
    node_id: str
    token: str
    protocol: str = "octopie/1"
    nonce: Optional[str] = None
    request_id: str = ""


@dataclass
class ExpansionOutcome:
    request: ExpansionRequest
    phase: ExpansionPhase
    admitted: bool
    reason: str = ""
    rejection: Optional[RejectionReason] = None


class ExpansionEngine:
    def __init__(self, head: "Head", event_log: Optional[EventLog] = None):
        self.head = head
        self.events = event_log or EventLog(policy_version="1")
        self._in_flight: Set[str] = set()
        self._completed: Set[str] = set()
        self._cancelled = False
        self._phase = ExpansionPhase.IDLE
        self._outcomes: List[ExpansionOutcome] = []

    @property
    def phase(self) -> ExpansionPhase:
        return self._phase

    def cancel(self) -> None:
        self._cancelled = True
        self._phase = ExpansionPhase.CANCELLED
        self.events.emit(EventType.EXPANSION_LIMITED, outcome="limited", reason_code="cancelled")

    def reset_cancel(self) -> None:
        self._cancelled = False
        self._phase = ExpansionPhase.IDLE

    def expand_one(self, req: ExpansionRequest, now: Optional[float] = None) -> ExpansionOutcome:
        if self._cancelled:
            out = ExpansionOutcome(req, ExpansionPhase.CANCELLED, False, "cancelled")
            self._outcomes.append(out)
            return out
        if req.node_id in self._completed:
            rec = self.head.topology.get(req.node_id)
            if rec and rec.state == NodeState.ADMITTED:
                out = ExpansionOutcome(req, ExpansionPhase.ADMIT, True, "already_admitted")
                self._outcomes.append(out)
                return out
        if req.node_id in self._in_flight:
            out = ExpansionOutcome(req, ExpansionPhase.PAUSED, False, "duplicate_in_flight")
            self._outcomes.append(out)
            self.events.emit(EventType.EXPANSION_LIMITED, outcome="limited", reason_code="duplicate_in_flight", node_id=req.node_id)
            return out
        self._in_flight.add(req.node_id)
        try:
            return self._run_phases(req, now)
        finally:
            self._in_flight.discard(req.node_id)

    def _run_phases(self, req: ExpansionRequest, now: Optional[float]) -> ExpansionOutcome:
        self.events.emit(EventType.EXPANSION_ATTEMPTED, outcome="info", node_id=req.node_id)
        self._phase = ExpansionPhase.DISCOVER
        if self.head.topology.get(req.node_id) is None:
            self.head.topology.add_discovered(req.node_id)
            self.events.emit(EventType.NODE_DISCOVERED, outcome="info", node_id=req.node_id)
        if self._cancelled:
            return self._fail(req, ExpansionPhase.CANCELLED, "cancelled")
        self._phase = ExpansionPhase.VERIFY
        if not self.head.is_available:
            self._phase = ExpansionPhase.PAUSED
            self.events.emit(EventType.EXPANSION_LIMITED, outcome="limited", reason_code="head_unavailable", node_id=req.node_id)
            return self._fail(req, ExpansionPhase.PAUSED, "head_unavailable", RejectionReason.HEAD_UNAVAILABLE)
        self._phase = ExpansionPhase.CHECK_CAPACITY
        if self.head.admitted_count() >= self.head.config.limits.max_nodes:
            self.events.emit(EventType.EXPANSION_LIMITED, outcome="limited", reason_code="capacity_exceeded", node_id=req.node_id)
            return self._fail(req, ExpansionPhase.PAUSED, "capacity_exceeded", RejectionReason.CAPACITY_EXCEEDED)
        self._phase = ExpansionPhase.ADMIT
        result: AdmissionResult = self.head.request_admission(
            req.node_id, req.token, protocol=req.protocol, nonce=req.nonce, now=now
        )
        if result.admitted:
            self._completed.add(req.node_id)
            self._phase = ExpansionPhase.MONITOR
            self.events.emit(EventType.NODE_ADMITTED, outcome="success", node_id=req.node_id)
            self.events.emit(EventType.EXPANSION_COMPLETED, outcome="success", node_id=req.node_id)
            out = ExpansionOutcome(req, ExpansionPhase.ADMIT, True, "admitted")
            self._outcomes.append(out)
            return out
        reason = result.reason.value if result.reason else result.message
        self.events.emit(EventType.ADMISSION_REJECTED, outcome="failure", reason_code=reason, node_id=req.node_id)
        self.events.emit(EventType.EXPANSION_LIMITED, outcome="limited", reason_code=reason, node_id=req.node_id)
        return self._fail(req, ExpansionPhase.PAUSED, reason, result.reason)

    def _fail(self, req, phase, reason, rejection=None):
        out = ExpansionOutcome(req, phase, False, reason, rejection)
        self._outcomes.append(out)
        return out

    def expand_batch(self, requests, now=None, stop_on_limit=True):
        results = []
        t = now if now is not None else time.time()
        for req in requests:
            if self._cancelled:
                break
            out = self.expand_one(req, now=t)
            results.append(out)
            if stop_on_limit and not out.admitted and out.rejection in (
                RejectionReason.CAPACITY_EXCEEDED,
                RejectionReason.RATE_LIMITED,
                RejectionReason.HEAD_UNAVAILABLE,
            ):
                self._phase = ExpansionPhase.PAUSED
                break
            t += 1.0 / max(self.head.config.limits.max_expansion_per_second, 1.0)
        self._phase = ExpansionPhase.REASSESS if not self._cancelled else ExpansionPhase.CANCELLED
        return results

    def outcomes(self):
        return list(self._outcomes)

    def admitted_this_session(self):
        return len(self._completed)
