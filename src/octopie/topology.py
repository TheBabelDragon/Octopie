"""Topology: known nodes, approved links, and lifecycle states.

States are distinct and ordered:

    DISCOVERED → AUTHENTICATED → AUTHORIZED → ADMITTED

Discovery never implies permission to join.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Optional, Set


class NodeState(Enum):
    DISCOVERED = auto()
    AUTHENTICATED = auto()
    AUTHORIZED = auto()
    ADMITTED = auto()
    DEGRADED = auto()
    ISOLATED = auto()
    REVOKED = auto()


# Valid forward transitions (others are rejected)
_ALLOWED_TRANSITIONS: Dict[NodeState, Set[NodeState]] = {
    NodeState.DISCOVERED: {NodeState.AUTHENTICATED, NodeState.REVOKED, NodeState.ISOLATED},
    NodeState.AUTHENTICATED: {NodeState.AUTHORIZED, NodeState.REVOKED, NodeState.ISOLATED},
    NodeState.AUTHORIZED: {NodeState.ADMITTED, NodeState.REVOKED, NodeState.ISOLATED},
    NodeState.ADMITTED: {NodeState.DEGRADED, NodeState.ISOLATED, NodeState.REVOKED},
    NodeState.DEGRADED: {NodeState.ADMITTED, NodeState.ISOLATED, NodeState.REVOKED},
    NodeState.ISOLATED: {NodeState.REVOKED},
    NodeState.REVOKED: set(),  # terminal
}


@dataclass
class NodeRecord:
    node_id: str
    state: NodeState = NodeState.DISCOVERED
    capabilities: frozenset[str] = field(default_factory=frozenset)
    last_seen: float = 0.0
    recovery_attempts: int = 0
    rejection_reason: Optional[str] = None
    link_to: Set[str] = field(default_factory=set)  # approved links only

    def can_transition_to(self, new_state: NodeState) -> bool:
        return new_state in _ALLOWED_TRANSITIONS.get(self.state, set())


class Topology:
    """In-memory view of the network known to the head."""

    def __init__(self) -> None:
        self._nodes: Dict[str, NodeRecord] = {}

    def add_discovered(self, node_id: str) -> NodeRecord:
        if node_id in self._nodes:
            return self._nodes[node_id]
        rec = NodeRecord(node_id=node_id, state=NodeState.DISCOVERED)
        self._nodes[node_id] = rec
        return rec

    def get(self, node_id: str) -> Optional[NodeRecord]:
        return self._nodes.get(node_id)

    def transition(self, node_id: str, new_state: NodeState, reason: Optional[str] = None) -> bool:
        rec = self._nodes.get(node_id)
        if rec is None:
            return False
        if not rec.can_transition_to(new_state):
            return False
        rec.state = new_state
        if reason is not None:
            rec.rejection_reason = reason
        if new_state == NodeState.REVOKED or new_state == NodeState.ISOLATED:
            rec.link_to.clear()
        return True

    def count_in_state(self, state: NodeState) -> int:
        return sum(1 for n in self._nodes.values() if n.state == state)

    def admitted_nodes(self) -> Dict[str, NodeRecord]:
        return {k: v for k, v in self._nodes.items() if v.state == NodeState.ADMITTED}

    def all_nodes(self) -> Dict[str, NodeRecord]:
        return dict(self._nodes)

    def approve_link(self, a: str, b: str) -> bool:
        """Approve a bidirectional link only if both nodes are ADMITTED."""
        ra = self._nodes.get(a)
        rb = self._nodes.get(b)
        if ra is None or rb is None:
            return False
        if ra.state != NodeState.ADMITTED or rb.state != NodeState.ADMITTED:
            return False
        ra.link_to.add(b)
        rb.link_to.add(a)
        return True

    def remove_node(self, node_id: str) -> None:
        self._nodes.pop(node_id, None)
