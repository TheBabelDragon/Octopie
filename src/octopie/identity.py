"""Node identity, credential verification, rotation, and revocation.

Uses the cryptography library for HMAC-based token verification.
Never stores private keys or live credentials in source or fixtures.
Simulation uses deterministic fake identities derived from a seed.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Optional, Set


class CredentialStatus(Enum):
    VALID = auto()
    EXPIRED = auto()
    REVOKED = auto()
    UNKNOWN = auto()


@dataclass(frozen=True)
class NodeIdentity:
    """Public identity of a node. No private material."""

    node_id: str
    public_key_fingerprint: str  # SHA-256 hex of a simulated public key
    capabilities: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.node_id or not self.node_id.strip():
            raise ValueError("node_id must be non-empty")


@dataclass
class Credential:
    """Short-lived admission credential. Never logged in full."""

    node_id: str
    token_hash: str  # HMAC-SHA256 of the token; token itself is ephemeral
    issued_at: float
    expires_at: float
    capabilities: frozenset[str]
    nonce: str

    def is_expired(self, now: Optional[float] = None) -> bool:
        return (now if now is not None else time.time()) >= self.expires_at


class IdentityStore:
    """In-memory identity and credential authority for the head.

    Production deployments would back this with a secure store and
    hardware-backed keys. This implementation is intentionally
    simulation-friendly and never persists secrets.
    """

    def __init__(self, head_secret: Optional[bytes] = None, seed: Optional[int] = None):
        # head_secret is used only for HMAC; if None a random one is generated
        # and kept only in memory for the lifetime of the process.
        if head_secret is None:
            if seed is not None:
                # Deterministic for reproducible tests
                head_secret = hashlib.sha256(f"octopie-seed-{seed}".encode()).digest()
            else:
                head_secret = secrets.token_bytes(32)
        self._head_secret = head_secret
        self._identities: Dict[str, NodeIdentity] = {}
        self._credentials: Dict[str, Credential] = {}  # node_id -> current credential
        self._revoked: Set[str] = set()
        self._used_nonces: Set[str] = set()
        self._authorized_ids: Set[str] = set()  # explicit authorization set

    def register_identity(self, identity: NodeIdentity) -> None:
        """Register a known identity. Does not grant authorization."""
        if identity.node_id in self._revoked:
            raise ValueError(f"cannot register revoked node {identity.node_id}")
        self._identities[identity.node_id] = identity

    def authorize(self, node_id: str) -> None:
        """Explicitly authorize a previously registered identity."""
        if node_id not in self._identities:
            raise ValueError(f"unknown identity {node_id}")
        if node_id in self._revoked:
            raise ValueError(f"cannot authorize revoked node {node_id}")
        self._authorized_ids.add(node_id)

    def is_authorized(self, node_id: str) -> bool:
        return node_id in self._authorized_ids and node_id not in self._revoked

    def issue_credential(
        self,
        node_id: str,
        capabilities: Optional[frozenset[str]] = None,
        ttl_seconds: float = 300.0,
        now: Optional[float] = None,
    ) -> str:
        """Issue a short-lived token. Returns the opaque token string.

        The token itself is returned to the caller (simulated node) and
        never stored in plaintext. Only its HMAC is retained.
        """
        if node_id not in self._identities:
            raise ValueError(f"unknown identity {node_id}")
        if node_id in self._revoked:
            raise ValueError(f"revoked node {node_id}")
        if node_id not in self._authorized_ids:
            raise ValueError(f"node {node_id} is not authorized")

        now = now if now is not None else time.time()
        nonce = secrets.token_hex(16)
        token = secrets.token_urlsafe(32)
        token_hash = self._hmac(token)
        caps = capabilities if capabilities is not None else self._identities[node_id].capabilities

        cred = Credential(
            node_id=node_id,
            token_hash=token_hash,
            issued_at=now,
            expires_at=now + ttl_seconds,
            capabilities=caps,
            nonce=nonce,
        )
        self._credentials[node_id] = cred
        return token

    def verify_credential(
        self,
        node_id: str,
        token: str,
        nonce: Optional[str] = None,
        now: Optional[float] = None,
    ) -> CredentialStatus:
        """Verify a presented token. Fail-closed on any anomaly."""
        if node_id in self._revoked:
            return CredentialStatus.REVOKED
        cred = self._credentials.get(node_id)
        if cred is None:
            return CredentialStatus.UNKNOWN
        if cred.is_expired(now):
            return CredentialStatus.EXPIRED
        if not hmac.compare_digest(cred.token_hash, self._hmac(token)):
            return CredentialStatus.UNKNOWN
        # Replay protection: nonces must be unique if provided
        if nonce is not None:
            if nonce in self._used_nonces:
                return CredentialStatus.UNKNOWN
            self._used_nonces.add(nonce)
        return CredentialStatus.VALID

    def revoke(self, node_id: str) -> None:
        """Immediately revoke identity and any outstanding credentials."""
        self._revoked.add(node_id)
        self._authorized_ids.discard(node_id)
        self._credentials.pop(node_id, None)

    def is_revoked(self, node_id: str) -> bool:
        return node_id in self._revoked

    def get_identity(self, node_id: str) -> Optional[NodeIdentity]:
        return self._identities.get(node_id)

    def list_authorized(self) -> Set[str]:
        return set(self._authorized_ids) - self._revoked

    def _hmac(self, data: str) -> str:
        return hmac.new(self._head_secret, data.encode(), hashlib.sha256).hexdigest()


def make_simulated_identity(node_id: str, capabilities: Optional[Set[str]] = None) -> NodeIdentity:
    """Create a deterministic fake identity for simulation/tests.

    No real cryptographic key material is generated or stored.
    """
    fingerprint = hashlib.sha256(f"sim-pubkey-{node_id}".encode()).hexdigest()
    caps = frozenset(capabilities or {"worker", "report_health"})
    return NodeIdentity(node_id=node_id, public_key_fingerprint=fingerprint, capabilities=caps)
