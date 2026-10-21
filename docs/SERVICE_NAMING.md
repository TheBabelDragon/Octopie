# Trust-Gated Service Naming and Identity Binding v0.1

## Purpose

Give services **stable, authorized names** that survive endpoint changes.
Octopie remains the authority for identity, admission, capability, and
publication permission. Aurora remains responsible for discovery, reachability,
routing, and transport.

This increment does **not** create a public DNS root, a commercial registrar,
a blockchain namespace, or automatic enrollment of unknown peers.

## Distinctions

| Concept | Owned by | Changes when |
|---------|----------|--------------|
| **Service name** (canonical) | Octopie naming policy | Explicit rename (not implemented in v0.1) |
| **Service identity** | Derived from name + owner | Never changes on endpoint update |
| **Publisher / owner identity** | Octopie `IdentityStore` | Explicit transfer (not automatic) |
| **Node identity** | Octopie admission | Node lifecycle |
| **Endpoint reference** | Publisher via Octopie | Authorized update / renewal |
| **Route / reachability** | Aurora | Network conditions |

A reachable endpoint is never proof of identity or ownership.

## Publication authorization model

1. Publisher must be a **registered** identity.
2. Publisher must be **explicitly authorized** by the head.
3. Publisher must not be **revoked**.
4. Optional short-lived credential may be verified (fail-closed).
5. Capability scope `publish_service` is required when the identity carries a non-empty capability set that does not include it (or `*`).
6. Ownership of an existing binding must match; takeover is rejected.
7. Binding versions are monotonic; stale `expected_version` produces `CONFLICT`.
8. Head unavailability rejects security-sensitive publication (`head_unavailable`).

Lookup is **not** a privilege. Anyone who can reach the naming API may request a binding; the result never grants publication rights.

## Name canonicalization

- Lowercased, trimmed.
- Regex: `^[a-z][a-z0-9_\-]{1,62}(\.[a-z][a-z0-9_\-]{0,62}){0,4}$`
- Malformed or ambiguous names are rejected with `invalid_service_name`.

Collisions are resolved by **first authorized owner**. A second publisher receives `ownership_mismatch`.

## Binding versioning and leases

- First publication creates `binding_version = 1`.
- Authorized endpoint change or non-identical update increments the version.
- Identical re-publish with valid auth refreshes the lease (`IDEMPOTENT`).
- Default lease 3600 s; hard ceiling 7 days.
- Expired bindings are returned as **not found** (`expired`) and marked `EXPIRED` in the store for auditability.
- Revoked bindings stay `REVOKED` and are not silently reassigned (v0.1).

## Revocation and failure behaviour

| Condition | Behaviour |
|-----------|-----------|
| Publisher revoked | Publication / renewal rejected; `revoke_owner_bindings` cascades |
| Binding revoked | Lookup returns not found; re-publish rejected |
| Expired lease | Lookup returns not found |
| Head unavailable | Publication fails closed |
| Stale version | `CONFLICT` |
| Duplicate correlation_id | Idempotent replay of prior decision |
| Unreachable endpoint | Ownership and identity unchanged (Aurora concern) |
| Incompatible contract version | `ContractError` |
| Missing endpoints / malformed name | Rejected |

Secrets (tokens, keys) never appear in serialized messages or audit output.

## Aurora–Octopie division

```
Publisher ──► ServicePublicationRequest ──► Octopie NamingService
                                              │ authorize + store binding
                                              ▼
                                    ServicePublicationDecision
                                              │
Aurora ◄── authorized service_id + endpoint refs ──┘
   │ resolve reachable routes via existing mesh / discovery
   │ report NodeObserved / health (never trust claims)
   ▼
Delivery / failover  (Aurora only)
```

Live Aurora integration is **pending**. This repository ships:

- Contract message types and serialization
- `NamingService` + `InMemoryBindingStore`
- `FakeAuroraAdapter`-style boundary already present for admission
- Documented adapter expectations

Standalone Octopie tests do not require a live Aurora process.

## Contract compatibility

Naming messages use the existing `octopie-aurora/1.0` version string and the
same `SUPPORTED_VERSIONS` set. Existing admission / membership / revocation
messages are unchanged. Consumers that only understand the original message
types continue to work; new message types are additive.

## Running tests

```bash
pip install -e ".[dev]"
pytest tests/test_service_naming.py tests/test_aurora_contract.py tests/test_head_architecture.py -q
```

## Implemented vs simulated

| Component | Status |
|-----------|--------|
| Service identity & binding model | Implemented |
| Trust-gated publication / update / revoke | Implemented |
| In-memory binding store | Implemented (replaceable interface) |
| Contract messages + round-trip | Implemented |
| Adversarial + regression tests | Implemented |
| Live Aurora endpoint resolution | **Not verified** — adapter boundary only |
| Persistent / replicated store | Out of scope |
| Public DNS / global root | Explicitly excluded |

## Minimal reference example

```python
from octopie import Head, HeadConfig
from octopie.identity import make_simulated_identity
from octopie.naming import (
    NamingService, EndpointRef, ServicePublicationRequest,
    ServiceBindingLookupRequest, CAPABILITY_PUBLISH_SERVICE,
)

head = Head(HeadConfig(seed=1))
identity = make_simulated_identity(
    "publisher-a",
    capabilities={CAPABILITY_PUBLISH_SERVICE},
)
head.register_and_authorize(identity)
token = head.issue_token("publisher-a")

naming = NamingService(head.identity)

decision = naming.publish(
    ServicePublicationRequest(
        service_name="field.kernel",
        publisher_id="publisher-a",
        endpoints=[EndpointRef("node-7:mesh")],
        requested_at=1_000_000.0,
        lease_seconds=600.0,
    ),
    token=token,
    now=1_000_000.0,
)
assert decision.outcome.value == "accepted"
assert decision.binding.service_id  # stable across endpoint changes

result = naming.lookup(
    ServiceBindingLookupRequest(service_name="field.kernel", requested_at=1_000_001.0),
    now=1_000_001.0,
)
assert result.found and result.binding.owner_id == "publisher-a"
```

## Why this is not universal public-DNS resolution

The namespace is **ecosystem-local**, gated by Octopie authorization, and has no
delegation path to the global DNS root or commercial registrars. It exists so
that Aurora × Octopie services can keep stable identities while endpoints move
across mesh nodes, without making any particular hosting provider or fixed IP
a fundamental architectural dependency.
