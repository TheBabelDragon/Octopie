"""Arm manager: dynamically allocate, pause, replace, and retire workers.

Provides a stable interface; concrete worker implementations are
pluggable. Node count, grouping, and worker count are independently
configurable — no hard-coded eight-arms or fixed group sizes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set


class WorkerState(Enum):
    IDLE = auto()
    RUNNING = auto()
    PAUSED = auto()
    RETIRED = auto()


@dataclass
class Worker:
    worker_id: str
    node_id: str
    state: WorkerState = WorkerState.IDLE
    group: Optional[str] = None


class ArmManager:
    """Allocate and lifecycle-manage workers attached to admitted nodes."""

    def __init__(self, max_workers: int = 256):
        self._max_workers = max_workers
        self._workers: Dict[str, Worker] = {}
        self._by_node: Dict[str, Set[str]] = {}

    def allocate(self, node_id: str, group: Optional[str] = None) -> Optional[Worker]:
        if len(self._workers) >= self._max_workers:
            return None
        worker_id = f"w-{node_id}-{len(self._workers)}"
        w = Worker(worker_id=worker_id, node_id=node_id, state=WorkerState.RUNNING, group=group)
        self._workers[worker_id] = w
        self._by_node.setdefault(node_id, set()).add(worker_id)
        return w

    def pause(self, worker_id: str) -> bool:
        w = self._workers.get(worker_id)
        if w is None or w.state != WorkerState.RUNNING:
            return False
        w.state = WorkerState.PAUSED
        return True

    def resume(self, worker_id: str) -> bool:
        w = self._workers.get(worker_id)
        if w is None or w.state != WorkerState.PAUSED:
            return False
        w.state = WorkerState.RUNNING
        return True

    def retire(self, worker_id: str) -> bool:
        w = self._workers.get(worker_id)
        if w is None:
            return False
        w.state = WorkerState.RETIRED
        self._by_node.get(w.node_id, set()).discard(worker_id)
        return True

    def retire_node(self, node_id: str) -> int:
        """Retire all workers for a node. Returns count retired."""
        ids = list(self._by_node.get(node_id, set()))
        for wid in ids:
            self.retire(wid)
        return len(ids)

    def replace(self, worker_id: str) -> Optional[Worker]:
        w = self._workers.get(worker_id)
        if w is None:
            return None
        self.retire(worker_id)
        return self.allocate(w.node_id, group=w.group)

    def workers_for(self, node_id: str) -> List[Worker]:
        return [self._workers[wid] for wid in self._by_node.get(node_id, set()) if wid in self._workers]

    def active_count(self) -> int:
        return sum(1 for w in self._workers.values() if w.state == WorkerState.RUNNING)
