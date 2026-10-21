"""Trust-gated service naming and identity binding (v0.1).

Separates:
  - human-readable service names
  - stable service identities
  - publisher / owner identities
  - network node identities
  - endpoint references
  - transport routes (owned by Aurora)

Octopie authorizes publication and ownership.
Aurora resolves authorized endpoint references to reachable routes.
Reachability never implies trust or ownership.
"""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Set

from .contract import CONTRACT_VERSION, ContractError
from .identity import IdentityStore

# ---------------------------------------------------------------------------
# Canonical name rules
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"^[a-z][a-z0-9_\-]{1,62}(\.[a-z][a-z0-9_\-]{0,62}){0,4}$")


def canonicalize_service_name(name: str) -> str:
    """Normalize and validate a service name. Raises ValueError on reject."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("service name must be a non-empty string")
    canonical = name.strip().lower()
    if not _NAME_RE.match(canonical):
        raise ValueError(
            f"invalid service name {name!r}: must match "
            r"^[a-z][a-z0-9_\-]{1,62}(\.[a-z][a-z0-9_\-]{0,62}){0,4}$"
        )
    return canonical


def stable_service_id(canonical_name: str, owner_id: str) -> str:
    """Deterministic service identity derived from name + owner (not endpoint)."""
    material = f"octopie-svc:{owner_id}:{canonical_name}".encode()
    return hashlib.sha256(material).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


class BindingStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING = "pending"


class PublicationOutcome(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    CONFLICT = "conflict"
    IDEMPOTENT = "idempotent"


@dataclass(frozen=True)
class EndpointRef:
    """Opaque endpoint reference. Aurora maps this to routes."""

    endpoint_id: str
    transport_hint: str = ""  # e.g. "tcp", "quic", "mesh" — advisory only
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.endpoint_id or not str(self.endpoint_id).strip():
            raise ValueError("endpoint_id must be non-empty")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "transport_hint": self.transport_hint,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EndpointRef":
        return cls(
            endpoint_id=str(d["endpoint_id"]),
            transport_hint=str(d.get("transport_hint", "")),
            metadata={str(k): str(v) for k, v in (d.get("metadata") or {}).items()},
        )


@dataclass(frozen=True)
class ServiceBinding:
    """Versioned, leased binding of a stable service identity to endpoints."""

    service_name: str
    service_id: str
    owner_id: str
    binding_version: int
    status: BindingStatus
    endpoints: tuple  # tuple[EndpointRef, ...]
    created_at: float
    updated_at: float
    expires_at: Optional[float]
    policy_version: str = "1"
    contract_version: str = CONTRACT_VERSION

    def is_expired(self, now: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        return (now if now is not None else time.time()) >= self.expires_at

    def is_trusted_active(self, now: Optional[float] = None) -> bool:
        return self.status == BindingStatus.ACTIVE and not self.is_expired(now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_name": self.service_name,
            "service_id": self.service_id,
            "owner_id": self.owner_id,
            "binding_version": self.binding_version,
            "status": self.status.value,
            "endpoints": [e.to_dict() if isinstance(e, EndpointRef) else e for e in self.endpoints],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "policy_version": self.policy_version,
            "contract_version": self.contract_version,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ServiceBinding":
        endpoints = tuple(
            EndpointRef.from_dict(e) if isinstance(e, dict) else e
            for e in (d.get("endpoints") or [])
        )
        return cls(
            service_name=str(d["service_name"]),
            service_id=str(d["service_id"]),
            owner_id=str(d["owner_id"]),
            binding_version=int(d["binding_version"]),
            status=BindingStatus(d["status"]),
            endpoints=endpoints,
            created_at=float(d["created_at"]),
            updated_at=float(d["updated_at"]),
            expires_at=float(d["expires_at"]) if d.get("expires_at") is not None else None,
            policy_version=str(d.get("policy_version", "1")),
            contract_version=str(d.get("contract_version", CONTRACT_VERSION)),
        )


# ---------------------------------------------------------------------------
# Contract messages (naming lifecycle)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServicePublicationRequest:
    service_name: str
    publisher_id: str
    endpoints: List[EndpointRef]
    requested_at: float
    lease_seconds: float = 3600.0
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    contract_version: str = CONTRACT_VERSION
    expected_version: Optional[int] = None  # for updates; None = create

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_name": self.service_name,
            "publisher_id": self.publisher_id,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "requested_at": self.requested_at,
            "lease_seconds": self.lease_seconds,
            "correlation_id": self.correlation_id,
            "contract_version": self.contract_version,
            "expected_version": self.expected_version,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ServicePublicationRequest":
        _require_version(d.get("contract_version", ""))
        endpoints = [EndpointRef.from_dict(e) for e in (d.get("endpoints") or [])]
        return cls(
            service_name=str(d["service_name"]),
            publisher_id=str(d["publisher_id"]),
            endpoints=endpoints,
            requested_at=float(d["requested_at"]),
            lease_seconds=float(d.get("lease_seconds", 3600.0)),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
            contract_version=str(d["contract_version"]),
            expected_version=int(d["expected_version"]) if d.get("expected_version") is not None else None,
        )


@dataclass(frozen=True)
class ServicePublicationDecision:
    service_name: str
    publisher_id: str
    outcome: PublicationOutcome
    reason_code: str
    decided_at: float
    binding: Optional[ServiceBinding] = None
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    policy_version: str = "1"
    contract_version: str = CONTRACT_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_name": self.service_name,
            "publisher_id": self.publisher_id,
            "outcome": self.outcome.value,
            "reason_code": self.reason_code,
            "decided_at": self.decided_at,
            "binding": self.binding.to_dict() if self.binding else None,
            "correlation_id": self.correlation_id,
            "policy_version": self.policy_version,
            "contract_version": self.contract_version,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ServicePublicationDecision":
        _require_version(d.get("contract_version", ""))
        binding = ServiceBinding.from_dict(d["binding"]) if d.get("binding") else None
        return cls(
            service_name=str(d["service_name"]),
            publisher_id=str(d["publisher_id"]),
            outcome=PublicationOutcome(d["outcome"]),
            reason_code=str(d.get("reason_code", "")),
            decided_at=float(d["decided_at"]),
            binding=binding,
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
            policy_version=str(d.get("policy_version", "1")),
            contract_version=str(d["contract_version"]),
        )


@dataclass(frozen=True)
class ServiceBindingLookupRequest:
    service_name: str
    requested_at: float
    requester_id: Optional[str] = None  # optional; lookup is not a privilege grant
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    contract_version: str = CONTRACT_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ServiceBindingLookupRequest":
        _require_version(d.get("contract_version", ""))
        return cls(
            service_name=str(d["service_name"]),
            requested_at=float(d["requested_at"]),
            requester_id=d.get("requester_id"),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
            contract_version=str(d["contract_version"]),
        )


@dataclass(frozen=True)
class ServiceBindingLookupResult:
    service_name: str
    found: bool
    decided_at: float
    binding: Optional[ServiceBinding] = None
    reason_code: str = ""
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    contract_version: str = CONTRACT_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_name": self.service_name,
            "found": self.found,
            "decided_at": self.decided_at,
            "binding": self.binding.to_dict() if self.binding else None,
            "reason_code": self.reason_code,
            "correlation_id": self.correlation_id,
            "contract_version": self.contract_version,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ServiceBindingLookupResult":
        _require_version(d.get("contract_version", ""))
        binding = ServiceBinding.from_dict(d["binding"]) if d.get("binding") else None
        return cls(
            service_name=str(d["service_name"]),
            found=bool(d["found"]),
            decided_at=float(d["decided_at"]),
            binding=binding,
            reason_code=str(d.get("reason_code", "")),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
            contract_version=str(d["contract_version"]),
        )


@dataclass(frozen=True)
class ServiceBindingRevocation:
    service_name: str
    service_id: str
    revoked_at: float
    reason_code: str
    revoked_by: str
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    policy_version: str = "1"
    contract_version: str = CONTRACT_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ServiceBindingRevocation":
        _require_version(d.get("contract_version", ""))
        return cls(
            service_name=str(d["service_name"]),
            service_id=str(d["service_id"]),
            revoked_at=float(d["revoked_at"]),
            reason_code=str(d.get("reason_code", "")),
            revoked_by=str(d["revoked_by"]),
            correlation_id=str(d.get("correlation_id", uuid.uuid4())),
            policy_version=str(d.get("policy_version", "1")),
            contract_version=str(d["contract_version"]),
        )


def _require_version(version: str) -> None:
    from .contract import SUPPORTED_VERSIONS

    if version not in SUPPORTED_VERSIONS:
        raise ContractError(
            "incompatible_contract_version",
            f"got {version!r}, supported={sorted(SUPPORTED_VERSIONS)}",
        )


# ---------------------------------------------------------------------------
# Storage interface + in-memory reference implementation
# ---------------------------------------------------------------------------


class BindingStoreProtocol(Protocol):
    def get(self, service_name: str) -> Optional[ServiceBinding]: ...
    def put(self, binding: ServiceBinding) -> None: ...
    def delete(self, service_name: str) -> None: ...
    def list_by_owner(self, owner_id: str) -> List[ServiceBinding]: ...


class InMemoryBindingStore:
    """Minimal deterministic binding store. Persistence is replaceable."""

    def __init__(self) -> None:
        self._by_name: Dict[str, ServiceBinding] = {}

    def get(self, service_name: str) -> Optional[ServiceBinding]:
        return self._by_name.get(service_name)

    def put(self, binding: ServiceBinding) -> None:
        self._by_name[binding.service_name] = binding

    def delete(self, service_name: str) -> None:
        self._by_name.pop(service_name, None)

    def list_by_owner(self, owner_id: str) -> List[ServiceBinding]:
        return [b for b in self._by_name.values() if b.owner_id == owner_id]

    def all_bindings(self) -> List[ServiceBinding]:
        return list(self._by_name.values())


# ---------------------------------------------------------------------------
# Naming service (authority)
# ---------------------------------------------------------------------------

# Capability that grants permission to publish service bindings.
CAPABILITY_PUBLISH_SERVICE = "publish_service"


class NamingService:
    """Trust-gated service naming authority.

    Uses IdentityStore for publisher authentication / authorization / revocation.
    Does not perform routing or discovery (Aurora's responsibility).
    """

    DEFAULT_LEASE_SECONDS = 3600.0
    MAX_LEASE_SECONDS = 86400.0 * 7  # 7 days hard ceiling

    def __init__(
        self,
        identity: IdentityStore,
        store: Optional[InMemoryBindingStore] = None,
        policy_version: str = "1",
        head_available: bool = True,
    ):
        self._identity = identity
        self._store = store or InMemoryBindingStore()
        self._policy_version = policy_version
        self._head_available = head_available
        self._seen_correlations: Set[str] = set()
        self._decisions: Dict[str, ServicePublicationDecision] = {}  # correlation_id -> decision

    def set_head_available(self, available: bool) -> None:
        self._head_available = available

    # ---- publication -------------------------------------------------------

    def publish(
        self,
        req: ServicePublicationRequest,
        *,
        now: Optional[float] = None,
        token: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> ServicePublicationDecision:
        """Authorize and record a service binding publication or update."""
        now = now if now is not None else time.time()

        # Idempotency on correlation_id
        if req.correlation_id in self._seen_correlations:
            existing = self._decisions.get(req.correlation_id)
            if existing is not None:
                return existing

        self._seen_correlations.add(req.correlation_id)

        def _decide(
            outcome: PublicationOutcome,
            reason: str,
            binding: Optional[ServiceBinding] = None,
        ) -> ServicePublicationDecision:
            d = ServicePublicationDecision(
                service_name=req.service_name,
                publisher_id=req.publisher_id,
                outcome=outcome,
                reason_code=reason,
                decided_at=now,
                binding=binding,
                correlation_id=req.correlation_id,
                policy_version=self._policy_version,
            )
            self._decisions[req.correlation_id] = d
            return d

        # Fail closed if control plane unavailable
        if not self._head_available:
            return _decide(PublicationOutcome.REJECTED, "head_unavailable")

        # Contract version already validated by from_dict; double-check
        try:
            _require_version(req.contract_version)
        except ContractError:
            return _decide(PublicationOutcome.REJECTED, "incompatible_contract_version")

        # Name validation
        try:
            canonical = canonicalize_service_name(req.service_name)
        except ValueError:
            return _decide(PublicationOutcome.REJECTED, "invalid_service_name")

        if not req.endpoints:
            return _decide(PublicationOutcome.REJECTED, "missing_endpoints")

        # Lease bounds
        lease = min(max(float(req.lease_seconds), 1.0), self.MAX_LEASE_SECONDS)

        # Publisher identity checks
        publisher = req.publisher_id
        if self._identity.is_revoked(publisher):
            return _decide(PublicationOutcome.REJECTED, "publisher_revoked")

        identity = self._identity.get_identity(publisher)
        if identity is None:
            return _decide(PublicationOutcome.REJECTED, "unknown_publisher")

        if not self._identity.is_authorized(publisher):
            return _decide(PublicationOutcome.REJECTED, "publisher_not_authorized")

        # Optional credential verification when token supplied
        if token is not None:
            from .identity import CredentialStatus

            status = self._identity.verify_credential(publisher, token, nonce=nonce, now=now)
            if status != CredentialStatus.VALID:
                return _decide(PublicationOutcome.REJECTED, f"invalid_credential:{status.name.lower()}")

        # Capability scope: require publish_service unless identity has unrestricted caps
        caps = identity.capabilities
        if CAPABILITY_PUBLISH_SERVICE not in caps and "*" not in caps:
            # Allow if the identity was authorized (explicit authz already checked);
            # capability is an additional fine-grained gate when present.
            # For v0.1 we treat missing capability as reject only when the set is non-empty
            # and does not contain the required scope.
            if caps and CAPABILITY_PUBLISH_SERVICE not in caps:
                return _decide(PublicationOutcome.REJECTED, "missing_capability_publish_service")

        existing = self._store.get(canonical)

        # Create path
        if existing is None:
            if req.expected_version is not None and req.expected_version != 0:
                return _decide(PublicationOutcome.CONFLICT, "expected_version_mismatch")

            svc_id = stable_service_id(canonical, publisher)
            binding = ServiceBinding(
                service_name=canonical,
                service_id=svc_id,
                owner_id=publisher,
                binding_version=1,
                status=BindingStatus.ACTIVE,
                endpoints=tuple(req.endpoints),
                created_at=now,
                updated_at=now,
                expires_at=now + lease,
                policy_version=self._policy_version,
            )
            self._store.put(binding)
            return _decide(PublicationOutcome.ACCEPTED, "published", binding)

        # Existing binding present
        if existing.status == BindingStatus.REVOKED:
            # Revoked names are not automatically reassigned
            if existing.owner_id != publisher:
                return _decide(PublicationOutcome.REJECTED, "name_revoked_ownership_locked")
            # Owner may re-publish after explicit head-side clearance only if we allow;
            # v0.1 keeps revoked permanent until store is cleared by authority.
            return _decide(PublicationOutcome.REJECTED, "binding_revoked")

        # Ownership check — prevent takeover
        if existing.owner_id != publisher:
            return _decide(PublicationOutcome.REJECTED, "ownership_mismatch")

        # Version check — prevent stale overwrite
        if req.expected_version is not None:
            if req.expected_version != existing.binding_version:
                return _decide(PublicationOutcome.CONFLICT, "stale_binding_version")

        # Idempotent re-publish of identical content
        same_endpoints = (
            len(existing.endpoints) == len(req.endpoints)
            and all(
                a.endpoint_id == b.endpoint_id
                for a, b in zip(existing.endpoints, req.endpoints)
            )
        )
        if same_endpoints and existing.is_trusted_active(now):
            # Treat as idempotent success; optionally refresh lease
            refreshed = ServiceBinding(
                service_name=existing.service_name,
                service_id=existing.service_id,
                owner_id=existing.owner_id,
                binding_version=existing.binding_version,
                status=BindingStatus.ACTIVE,
                endpoints=existing.endpoints,
                created_at=existing.created_at,
                updated_at=now,
                expires_at=now + lease,
                policy_version=self._policy_version,
            )
            self._store.put(refreshed)
            return _decide(PublicationOutcome.IDEMPOTENT, "idempotent_refresh", refreshed)

        # Authorized update (endpoint change or renewal)
        new_version = existing.binding_version + 1
        updated = ServiceBinding(
            service_name=existing.service_name,
            service_id=existing.service_id,  # identity preserved
            owner_id=existing.owner_id,
            binding_version=new_version,
            status=BindingStatus.ACTIVE,
            endpoints=tuple(req.endpoints),
            created_at=existing.created_at,
            updated_at=now,
            expires_at=now + lease,
            policy_version=self._policy_version,
        )
        self._store.put(updated)
        return _decide(PublicationOutcome.ACCEPTED, "updated", updated)

    # ---- lookup ------------------------------------------------------------

    def lookup(
        self,
        req: ServiceBindingLookupRequest,
        *,
        now: Optional[float] = None,
    ) -> ServiceBindingLookupResult:
        """Return the current trusted binding if any. Lookup never grants publish rights."""
        now = now if now is not None else time.time()

        try:
            canonical = canonicalize_service_name(req.service_name)
        except ValueError:
            return ServiceBindingLookupResult(
                service_name=req.service_name,
                found=False,
                decided_at=now,
                reason_code="invalid_service_name",
                correlation_id=req.correlation_id,
            )

        binding = self._store.get(canonical)
        if binding is None:
            return ServiceBindingLookupResult(
                service_name=canonical,
                found=False,
                decided_at=now,
                reason_code="not_found",
                correlation_id=req.correlation_id,
            )

        if binding.status == BindingStatus.REVOKED:
            return ServiceBindingLookupResult(
                service_name=canonical,
                found=False,
                decided_at=now,
                reason_code="revoked",
                correlation_id=req.correlation_id,
            )

        if binding.is_expired(now):
            # Mark expired but do not delete (auditability)
            expired = ServiceBinding(
                service_name=binding.service_name,
                service_id=binding.service_id,
                owner_id=binding.owner_id,
                binding_version=binding.binding_version,
                status=BindingStatus.EXPIRED,
                endpoints=binding.endpoints,
                created_at=binding.created_at,
                updated_at=binding.updated_at,
                expires_at=binding.expires_at,
                policy_version=binding.policy_version,
            )
            self._store.put(expired)
            return ServiceBindingLookupResult(
                service_name=canonical,
                found=False,
                decided_at=now,
                reason_code="expired",
                correlation_id=req.correlation_id,
            )

        if not binding.is_trusted_active(now):
            return ServiceBindingLookupResult(
                service_name=canonical,
                found=False,
                decided_at=now,
                reason_code="not_active",
                correlation_id=req.correlation_id,
            )

        return ServiceBindingLookupResult(
            service_name=canonical,
            found=True,
            decided_at=now,
            binding=binding,
            reason_code="ok",
            correlation_id=req.correlation_id,
        )

    # ---- revocation --------------------------------------------------------

    def revoke(
        self,
        service_name: str,
        revoked_by: str,
        reason_code: str = "revoked",
        *,
        now: Optional[float] = None,
    ) -> Optional[ServiceBindingRevocation]:
        """Explicitly revoke a binding. Only owner or head authority may revoke."""
        now = now if now is not None else time.time()
        try:
            canonical = canonicalize_service_name(service_name)
        except ValueError:
            return None

        binding = self._store.get(canonical)
        if binding is None:
            return None

        # Only owner or a non-revoked authorized identity acting as head may revoke.
        # In this single-head design the caller is trusted to be the head when
        # revoked_by is the head identity; ownership check is the primary gate.
        if binding.owner_id != revoked_by and not self._identity.is_authorized(revoked_by):
            return None

        revoked = ServiceBinding(
            service_name=binding.service_name,
            service_id=binding.service_id,
            owner_id=binding.owner_id,
            binding_version=binding.binding_version,
            status=BindingStatus.REVOKED,
            endpoints=binding.endpoints,
            created_at=binding.created_at,
            updated_at=now,
            expires_at=binding.expires_at,
            policy_version=binding.policy_version,
        )
        self._store.put(revoked)
        return ServiceBindingRevocation(
            service_name=canonical,
            service_id=binding.service_id,
            revoked_at=now,
            reason_code=reason_code,
            revoked_by=revoked_by,
            policy_version=self._policy_version,
        )

    def revoke_owner_bindings(self, owner_id: str, *,
                             now: Optional[float] = None) -> List[ServiceBindingRevocation]:
        """Revoke all bindings owned by a publisher (e.g. on publisher revocation)."""
        now = now if now is not None else time.time()
        revs: List[ServiceBindingRevocation] = []
        for b in list(self._store.list_by_owner(owner_id)):
            if b.status != BindingStatus.REVOKED:
                r = self.revoke(b.service_name, revoked_by=owner_id, reason_code="owner_revoked", now=now)
                if r:
                    revs.append(r)
        return revs
