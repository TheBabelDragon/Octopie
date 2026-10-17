"""Deterministic network growth, admission, failures, revocation, and recovery
without requiring real external peers.

Uses a fixed seed for reproducible runs.
"""

from __future__ import annotations

import random
from typing import List, Optional, Set

from .config import HeadConfig
from .head import Head
from .identity import make_simulated_identity
from .topology import NodeState


class NetworkSimulator:
    """Drive a Head through a controlled, deterministic scenario."""

    def __init__(self, config: Optional[HeadConfig] = None):
        self.config = config or HeadConfig(seed=42)
        if self.config.seed is None:
            object.__setattr__(self.config, "seed", 42)
        self.head = Head(self.config)
        self.rng = random.Random(self.config.seed)
        self._tokens: dict[str, str] = {}
        self._node_ids: List[str] = []

    def bootstrap_identities(self, count: Optional[int] = None) -> List[str]:
        """Register and authorize `count` simulated nodes (default = target_nodes)."""
        n = count if count is not None else self.config.target_nodes
        ids = []
        for i in range(n):
            node_id = f"node-{i:04d}"
            identity = make_simulated_identity(node_id)
            self.head.register_and_authorize(identity)
            token = self.head.issue_token(node_id)
            self._tokens[node_id] = token
            ids.append(node_id)
        self._node_ids = ids
        return ids

    def grow_to_target(self, target: Optional[int] = None) -> int:
        """Admit nodes until target (or config.target_nodes) is reached.

        Advances a simulated clock between admissions so rate limits do not
        artificially cap a single burst. Returns number successfully admitted.
        """
        target = target if target is not None else self.config.target_nodes
        if not self._node_ids:
            self.bootstrap_identities(max(target, self.config.target_nodes))

        admitted = 0
        t = 1_000_000.0  # fixed base timestamp for determinism
        for node_id in self._node_ids:
            if admitted >= target:
                break
            rec = self.head.topology.get(node_id)
            if rec is not None and rec.state == NodeState.ADMITTED:
                admitted += 1
                continue
            result = self.head.request_admission(
                node_id, self._tokens[node_id], now=t
            )
            if result.admitted:
                admitted += 1
            t += 1.0 / max(self.config.limits.max_expansion_per_second, 1.0)
        return admitted

    def inject_unauthenticated(self) -> bool:
        """Attempt admission of a node that was never registered. Must fail."""
        node_id = "ghost-9999"
        result = self.head.request_admission(node_id, "fake-token")
        return not result.admitted

    def inject_unauthorized(self) -> bool:
        """Register but do not authorize, then attempt admission. Must fail."""
        node_id = "unauth-0001"
        identity = make_simulated_identity(node_id)
        self.head.identity.register_identity(identity)
        try:
            token = self.head.identity.issue_credential(node_id)
        except ValueError:
            token = "dummy"
        result = self.head.request_admission(node_id, token)
        return not result.admitted and result.reason is not None

    def revoke_and_verify(self, node_id: str) -> bool:
        """Revoke an admitted node and confirm it loses capabilities."""
        self.head.revoke(node_id)
        rec = self.head.topology.get(node_id)
        if rec is None or rec.state != NodeState.REVOKED:
            return False
        token = self._tokens.get(node_id, "stale")
        result = self.head.request_admission(node_id, token)
        return not result.admitted

    def peer_cannot_confer_trust(self) -> bool:
        """An admitted peer cannot authorize another node."""
        outsider = "peer-pushed-0001"
        identity = make_simulated_identity(outsider)
        self.head.identity.register_identity(identity)
        try:
            self.head.identity.issue_credential(outsider)
            return False
        except ValueError:
            pass
        result = self.head.request_admission(outsider, "any")
        return not result.admitted

    def run_failure_and_recovery(self, node_id: str) -> bool:
        """Report failure, confirm bounded recovery, no limit breach."""
        before = self.head.admitted_count()
        self.head.health.report_failure(node_id, detail="simulated crash")
        for _ in range(self.config.limits.recovery_max_attempts + 2):
            self.head.health.report_failure(node_id, detail="retry")
        rec = self.head.topology.get(node_id)
        after = self.head.admitted_count()
        return after <= before and rec is not None and rec.state in (NodeState.ISOLATED, NodeState.DEGRADED, NodeState.REVOKED)

    def head_loss_pauses_admissions(self) -> bool:
        """During head loss, new admissions are rejected; no extra privileges granted."""
        self.head.simulate_head_loss()
        spare = f"spare-{self.rng.randint(10000, 99999)}"
        identity = make_simulated_identity(spare)
        self.head.register_and_authorize(identity)
        token = self.head.issue_token(spare)
        result = self.head.request_admission(spare, token)
        paused_ok = not result.admitted
        self.head.recover_from_head_loss()
        return paused_ok
