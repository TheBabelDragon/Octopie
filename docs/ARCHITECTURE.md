# Octopie Architecture

## Purpose and boundaries

Octopie is a **head-controlled, policy-bounded** control plane for a network of
explicitly authorized worker nodes. The default simulation target is **42**
nodes; larger targets are configuration, not new code.

Octopie does **not**:
- Scan the public internet or auto-enroll arbitrary peers
- Propagate trust from one node to another
- Run distributed consensus (single-head in this version)
- Store private keys or live tokens in snapshots or logs
- Act as a global DNS root or commercial name registrar

## Module responsibilities

| Module | Responsibility |
|--------|----------------|
| `config` | Typed, validated HeadConfig / LimitsConfig / SimulationConfig / AuditConfig |
| `identity` | Registration, HMAC credentials, explicit authorization, revocation |
| `topology` | Lifecycle state machine and approved links |
| `admission` | Fail-closed gate: authn → authz → capacity → rate |
| `expansion` | Bounded DISCOVER→…→ADMIT engine with backpressure and idempotency |
| `health` | Heartbeats, timeouts, bounded recovery |
| `arm` | Worker allocate / pause / replace / retire |
| `limits` | Expansion rate and concurrency |
| `events` | Structured event contract with optional hash chain |
| `audit` | Legacy simple audit log (redacting) |
| `persistence` | Versioned atomic snapshots; revocations survive restore |
| `diagnostics` | Read-only explain-why reports |
| `simulation` | Deterministic scenarios + SimulationSummary |
| `adapters` | Optional inbound observation interfaces (Aurora / REA / CANtheon contracts) |
| `contract` | Versioned Octopie↔Aurora messages (admission, membership, health) |
| `naming` | Trust-gated service names, bindings, leases, revocation (v0.1) |
| `head` | Orchestration, safe shutdown, outage behaviour |

## Trust states and legal transitions

```
DISCOVERED → AUTHENTICATED → AUTHORIZED → ADMITTED
                                           ↓
                                      DEGRADED ↔ ADMITTED
                                           ↓
                                       ISOLATED → REVOKED
```

Invalid transitions are rejected by `NodeRecord.can_transition_to`.

## Service naming (v0.1)

Stable service identities are independent of network endpoints. Publication is
authorized by the same identity and capability machinery as admission. See
[SERVICE_NAMING.md](SERVICE_NAMING.md) and the naming messages in the Aurora
contract document.

## Persistence and recovery

1. `build_snapshot_from_head` captures identities, topology, and revocations (no secrets).
2. `Store.save` writes atomically (temp + rename).
3. On load, incompatible schema or corrupt JSON fails closed.
4. `apply_snapshot_to_head` restores revocations first (they win), restores authorized set,
   maps former ADMITTED → AUTHORIZED (forces re-admission), and pauses admissions for revalidation.

## Expansion backpressure

`ExpansionEngine` refuses work when:
- Head is unavailable
- Capacity (`max_nodes`) is reached
- Rate limit is hit
- Duplicate in-flight request for the same node
- Engine has been cancelled

## Adapter boundaries

`adapters.py` defines abstract contracts only. Null implementations ship by default.
Integrators supply concrete adapters; they must never call `authorize` or `request_admission`.

## Diagnostics

```python
from octopie import diagnose, explain_rejection
report = diagnose(head)
print(report.summary())
print(explain_rejection(head, "node-0001"))
```

## Roadmap

1. Lease renewal protocol for admitted nodes
2. Multi-head authority transfer (interfaces reserved)
3. Hardware-backed identity store
4. Concrete Aurora / REA / CANtheon adapters once their contracts are stable
5. Live Aurora resolution of authorized service bindings to routes
