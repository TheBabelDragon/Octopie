"""Read-only diagnostics for admission, expansion, topology, and head health.

Explains why nodes were rejected, why expansion stopped, which limits were
hit, and whether the 42-node (or configured) target is achievable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .topology import NodeState

if TYPE_CHECKING:
    from .head import Head


@dataclass
class DiagnosticReport:
    head_healthy: bool
    admissions_paused: bool
    target_nodes: int
    admitted: int
    authorized: int
    discovered: int
    revoked: int
    degraded: int
    isolated: int
    target_achievable: bool
    target_gap: int
    limiting_factors: List[str] = field(default_factory=list)
    topology_consistent: bool = True
    topology_issues: List[str] = field(default_factory=list)
    recent_rejections: List[Dict[str, str]] = field(default_factory=list)
    resource_summary: Dict[str, Any] = field(default_factory=dict)
    recovery_safe: bool = True
    messages: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def summary(self) -> str:
        lines = [
            f"Head healthy: {self.head_healthy}  paused: {self.admissions_paused}",
            f"Admitted {self.admitted}/{self.target_nodes}  "
            f"(authorized={self.authorized} discovered={self.discovered} "
            f"revoked={self.revoked} degraded={self.degraded} isolated={self.isolated})",
            f"Target achievable: {self.target_achievable}  gap: {self.target_gap}",
        ]
        if self.limiting_factors:
            lines.append("Limits: " + "; ".join(self.limiting_factors))
        if not self.topology_consistent:
            lines.append("Topology issues: " + "; ".join(self.topology_issues))
        if self.recent_rejections:
            lines.append(f"Recent rejections: {len(self.recent_rejections)}")
            for r in self.recent_rejections[:5]:
                lines.append(f"  - {r.get('node_id', '?')}: {r.get('reason', '?')}")
        for m in self.messages:
            lines.append(m)
        return "\n".join(lines)


def diagnose(head: "Head") -> DiagnosticReport:
    topo = head.topology
    admitted = topo.count_in_state(NodeState.ADMITTED)
    authorized = len(head.identity.list_authorized())
    discovered = topo.count_in_state(NodeState.DISCOVERED)
    revoked = topo.count_in_state(NodeState.REVOKED)
    degraded = topo.count_in_state(NodeState.DEGRADED)
    isolated = topo.count_in_state(NodeState.ISOLATED)
    target = head.config.target_nodes
    max_nodes = head.config.limits.max_nodes

    limiting: List[str] = []
    if admitted >= max_nodes:
        limiting.append(f"max_nodes={max_nodes} reached")
    if not head.is_available:
        limiting.append("head unavailable / admissions paused")
    if authorized < target:
        limiting.append(f"only {authorized} authorized identities (need {target})")
    available_slots = max_nodes - admitted
    if available_slots < (target - admitted) and target > admitted:
        limiting.append(f"only {available_slots} capacity slots remain")

    gap = max(0, target - admitted)
    achievable = (
        head.is_available
        and authorized >= target
        and max_nodes >= target
        and gap <= available_slots
    )

    issues: List[str] = []
    for nid, rec in topo.admitted_nodes().items():
        if head.identity.is_revoked(nid):
            issues.append(f"{nid} is ADMITTED but revoked")
        if not head.identity.is_authorized(nid):
            issues.append(f"{nid} is ADMITTED but not authorized")

    rejections: List[Dict[str, str]] = []
    for nid, rec in topo.all_nodes().items():
        if rec.rejection_reason:
            rejections.append({"node_id": nid, "reason": rec.rejection_reason})

    recovery_safe = head.config.fail_closed_on_policy_error and head.config.require_explicit_authorization

    messages: List[str] = []
    if gap == 0:
        messages.append("Target reached.")
    elif achievable:
        messages.append(f"Target of {target} is achievable; {gap} admissions remaining.")
    else:
        messages.append(f"Target of {target} is NOT currently achievable.")

    return DiagnosticReport(
        head_healthy=head.is_available,
        admissions_paused=getattr(head, "_admissions_paused", False),
        target_nodes=target,
        admitted=admitted,
        authorized=authorized,
        discovered=discovered,
        revoked=revoked,
        degraded=degraded,
        isolated=isolated,
        target_achievable=achievable,
        target_gap=gap,
        limiting_factors=limiting,
        topology_consistent=len(issues) == 0,
        topology_issues=issues,
        recent_rejections=rejections,
        resource_summary={
            "max_nodes": max_nodes,
            "max_connections": head.config.limits.max_connections,
            "max_expansion_per_second": head.config.limits.max_expansion_per_second,
            "active_workers": head.arms.active_count(),
        },
        recovery_safe=recovery_safe,
        messages=messages,
    )


def explain_rejection(head: "Head", node_id: str) -> str:
    rec = head.topology.get(node_id)
    if rec is None:
        return f"{node_id}: never discovered"
    if rec.state == NodeState.ADMITTED:
        return f"{node_id}: currently ADMITTED"
    if rec.state == NodeState.REVOKED:
        return f"{node_id}: REVOKED ({rec.rejection_reason or 'no reason'})"
    if rec.rejection_reason:
        return f"{node_id}: state={rec.state.name} reason={rec.rejection_reason}"
    if not head.identity.get_identity(node_id):
        return f"{node_id}: unknown identity (unauthenticated)"
    if head.identity.is_revoked(node_id):
        return f"{node_id}: identity revoked"
    if not head.identity.is_authorized(node_id):
        return f"{node_id}: registered but not explicitly authorized"
    if not head.is_available:
        return f"{node_id}: head control plane unavailable"
    admitted = head.admitted_count()
    if admitted >= head.config.limits.max_nodes:
        return f"{node_id}: capacity exceeded ({admitted}/{head.config.limits.max_nodes})"
    return f"{node_id}: state={rec.state.name}, no recorded rejection"
