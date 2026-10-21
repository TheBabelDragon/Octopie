# Octopie ↔ Aurora Integration Contract

**Contract version:** `octopie-aurora/1.0`

## Division of responsibility

```mermaid
flowchart LR
  subgraph Aurora["Aurora (network layer)"]
    Mesh[Mesh / Discovery]
    Route[Routing / Transport]
    Health[Health observations]
  end
  subgraph Contract["Contract octopie-aurora/1.0"]
    NO[NodeObserved]
    AR[AdmissionRequested]
    AD[AdmissionDecision]
    MS[MembershipSnapshot]
    NR[NodeRevocation]
    SP[ServicePublication*]
    SL[ServiceBindingLookup*]
  end
  subgraph Octopie["Octopie (trust layer)"]
    ID[Identity / Authz]
    Admit[Admission gate]
    Policy[Budgets / Expansion]
    Naming[Service naming]
  end
  Mesh -->|NodeObserved| NO
  Health -->|NodeHealthObserved| NO
  NO --> ID
  AR --> Admit
  Admit --> AD
  Admit --> MS
  Admit --> NR
  AD -.->|cache with TTL, fail-closed| Route
  SP --> Naming
  Naming --> SP
  SL --> Naming
  Naming -->|authorized endpoint refs| Route
```

| State | Authority |
|-------|-----------|
| Network reachability, routes, delivery | **Aurora** |
| Trusted membership, admission, revocation | **Octopie** |
| Authorization / capability policy | **Octopie** |
| Service publication, ownership, binding integrity | **Octopie** |
| Resource budgets, expansion limits | **Octopie** |
| Artifact integrity / history | **Aurora** |
| Integration health | Shared (`CoordinationStatus`) |

**Hard rule:** transport success is never admission. Discovery is never trust.
Reachability is never ownership of a service name.

## Message types

| Message | Direction | Purpose |
|---------|-----------|---------|
| `NodeObserved` | Aurora → Octopie | Peer seen; not a trust claim |
| `AdmissionRequested` | Aurora → Octopie | Ask for a decision |
| `AdmissionDecision` | Octopie → Aurora | Admit / reject / defer / revoke |
| `MembershipSnapshot` | Octopie → Aurora | Admitted node IDs only |
| `CapabilityDecision` | Octopie → Aurora | Capability grant/deny |
| `NodeHealthObserved` | Aurora → Octopie | Advisory health |
| `NodeRevocation` | Octopie → Aurora | Immediate trust removal |
| `CoordinationStatus` | Either | Boundary health |
| `ServicePublicationRequest` | Publisher / Aurora → Octopie | Request authorized binding |
| `ServicePublicationDecision` | Octopie → caller | Accept / reject / conflict / idempotent |
| `ServiceBindingLookupRequest` | Any → Octopie | Resolve name to binding |
| `ServiceBindingLookupResult` | Octopie → caller | Trusted binding or not-found |
| `ServiceBindingRevocation` | Octopie → callers | Explicit name/binding revocation |

Every decision includes: `outcome` / `reason_code`, `policy_version`, `contract_version`, `decided_at`, `correlation_id`, optional `expires_at` / lease.

Naming messages are defined in `octopie.naming` and use the same `octopie-aurora/1.0` version. See [SERVICE_NAMING.md](SERVICE_NAMING.md).

## Trust outcomes

- `observed_unverified`
- `authenticated_not_authorized`
- `authorized_not_admitted`
- `admitted_active`
- `degraded` / `isolated` / `revoked` / `rejected`

## Behaviour on failure

| Condition | Required behaviour |
|-----------|-------------------|
| Incompatible `contract_version` | Reject (`ContractError`) |
| Missing credential on admission request | Reject (`missing_credential`) |
| Expired decision (`expires_at`) | Aurora must not treat as valid trust |
| Duplicate `correlation_id` | Idempotent; no double membership |
| Octopie unavailable | Aurora pauses **new** security-sensitive admissions and publications; existing authorized work continues only within Aurora's own already-configured boundaries |
| Malformed payload | Reject; do not grant privileges |
| Unauthorized / revoked publisher | Publication rejected; no binding mutation |
| Stale binding version | `CONFLICT`; no overwrite |
| Expired or revoked binding | Lookup returns not-found; not treated as trusted |

## Safe defaults

- Integration **disabled / observe-only** until explicitly configured on Aurora.
- No automatic enrollment of unknown public peers.
- Peer recommendations never bypass Octopie authorization.
- Secrets never appear in contract messages or logs.
- Service names are ecosystem-local; this is not a global DNS root.

## Running isolated tests

```bash
cd Octopie
pip install -e ".[dev]"
pytest tests/test_aurora_contract.py tests/test_head_architecture.py tests/test_service_naming.py -q
```

## Enabling on Aurora

See Aurora `docs/OCTOPIE_INTEGRATION.md`. Set observe-only off only after contract version match, decision TTL, and revocation path are verified.
Live service-name → route resolution against a real Aurora process is **not** verified in this repository increment.
