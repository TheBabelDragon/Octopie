"""Versioned persistence for identities, topology, revocations, and audit checkpoints.

Uses atomic file writes (write-temp + rename). No external database required.
Corrupt or incompatible state fails safely. Revocations are never silently
undone by a stale snapshot. Recovery revalidates policy before admissions.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

SCHEMA_VERSION = 1


@dataclass
class RevocationRecord:
    node_id: str
    revoked_at: float
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RevocationRecord":
        return cls(node_id=d["node_id"], revoked_at=d["revoked_at"], reason=d.get("reason", ""))


@dataclass
class NodeSnapshot:
    node_id: str
    state: str
    capabilities: List[str] = field(default_factory=list)
    recovery_attempts: int = 0
    rejection_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "NodeSnapshot":
        return cls(
            node_id=d["node_id"],
            state=d["state"],
            capabilities=list(d.get("capabilities", [])),
            recovery_attempts=int(d.get("recovery_attempts", 0)),
            rejection_reason=d.get("rejection_reason"),
        )


@dataclass
class PersistenceSnapshot:
    schema_version: int
    saved_at: float
    head_id: str
    policy_version: str
    authorized_ids: List[str]
    revoked: List[RevocationRecord]
    nodes: List[NodeSnapshot]
    audit_checkpoint: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "saved_at": self.saved_at,
            "head_id": self.head_id,
            "policy_version": self.policy_version,
            "authorized_ids": list(self.authorized_ids),
            "revoked": [r.to_dict() for r in self.revoked],
            "nodes": [n.to_dict() for n in self.nodes],
            "audit_checkpoint": list(self.audit_checkpoint),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PersistenceSnapshot":
        version = int(d.get("schema_version", 0))
        if version != SCHEMA_VERSION:
            raise ValueError(f"incompatible schema version {version}; expected {SCHEMA_VERSION}")
        return cls(
            schema_version=version,
            saved_at=float(d["saved_at"]),
            head_id=str(d["head_id"]),
            policy_version=str(d.get("policy_version", "1")),
            authorized_ids=list(d.get("authorized_ids", [])),
            revoked=[RevocationRecord.from_dict(r) for r in d.get("revoked", [])],
            nodes=[NodeSnapshot.from_dict(n) for n in d.get("nodes", [])],
            audit_checkpoint=list(d.get("audit_checkpoint", [])),
        )


class Store:
    def __init__(self, directory: str | Path):
        self.root = Path(directory)
        self.root.mkdir(parents=True, exist_ok=True)
        self._path = self.root / "snapshot.json"

    def save(self, snapshot: PersistenceSnapshot) -> None:
        data = json.dumps(snapshot.to_dict(), indent=2, sort_keys=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.root), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, str(self._path))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def load(self) -> Optional[PersistenceSnapshot]:
        if not self._path.exists():
            return None
        try:
            raw = self._path.read_text()
            data = json.loads(raw)
            return PersistenceSnapshot.from_dict(data)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            raise ValueError(f"corrupt or incompatible snapshot: {e}") from e

    def exists(self) -> bool:
        return self._path.exists()

    def clear(self) -> None:
        if self._path.exists():
            self._path.unlink()


def build_snapshot_from_head(head: Any, policy_version: str = "1") -> PersistenceSnapshot:
    from .topology import NodeState
    revoked = [
        RevocationRecord(node_id=nid, revoked_at=time.time(), reason="persisted")
        for nid, rec in head.topology.all_nodes().items()
        if rec.state == NodeState.REVOKED
    ]
    for nid in getattr(head.identity, "_revoked", set()):
        if not any(r.node_id == nid for r in revoked):
            revoked.append(RevocationRecord(node_id=nid, revoked_at=time.time(), reason="identity_revoked"))
    nodes = [
        NodeSnapshot(
            node_id=nid,
            state=rec.state.name,
            capabilities=list(rec.capabilities),
            recovery_attempts=rec.recovery_attempts,
            rejection_reason=rec.rejection_reason,
        )
        for nid, rec in head.topology.all_nodes().items()
    ]
    return PersistenceSnapshot(
        schema_version=SCHEMA_VERSION,
        saved_at=time.time(),
        head_id=head.config.head_id,
        policy_version=policy_version,
        authorized_ids=sorted(head.identity.list_authorized()),
        revoked=revoked,
        nodes=nodes,
        audit_checkpoint=head.audit.events()[-50:] if hasattr(head, "audit") else [],
    )


def apply_snapshot_to_head(head: Any, snapshot: PersistenceSnapshot, revalidate: bool = True) -> None:
    from .topology import NodeState
    from .identity import make_simulated_identity
    revoked_ids = {r.node_id for r in snapshot.revoked}
    for rid in revoked_ids:
        head.identity.revoke(rid)
        if head.topology.get(rid) is None:
            head.topology.add_discovered(rid)
        head.topology.transition(rid, NodeState.REVOKED, "restored revocation")
    for nid in snapshot.authorized_ids:
        if nid in revoked_ids:
            continue
        if head.identity.get_identity(nid) is None:
            head.identity.register_identity(make_simulated_identity(nid))
        try:
            head.identity.authorize(nid)
        except ValueError:
            pass
    for ns in snapshot.nodes:
        if ns.node_id in revoked_ids:
            continue
        rec = head.topology.get(ns.node_id)
        if rec is None:
            rec = head.topology.add_discovered(ns.node_id)
        target = ns.state
        if target == "ADMITTED":
            target = "AUTHORIZED"
        try:
            desired = NodeState[target]
        except KeyError:
            desired = NodeState.DISCOVERED
        for step in (NodeState.AUTHENTICATED, NodeState.AUTHORIZED):
            if rec.state != desired and rec.can_transition_to(step):
                head.topology.transition(ns.node_id, step)
        rec.recovery_attempts = ns.recovery_attempts
        rec.rejection_reason = ns.rejection_reason
    if revalidate:
        head.pause_admissions(reason="post_recovery_revalidation")
