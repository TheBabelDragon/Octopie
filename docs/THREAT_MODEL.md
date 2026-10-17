# Octopie Threat Model

## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Head control plane | Sole authority for identity registration, authorization, admission policy, and revocation. |
| Admitted nodes | Receive only explicitly granted capability scopes. Cannot authorize peers. |
| Discovered peers | Visible but untrusted until AUTHENTICATED → AUTHORIZED → ADMITTED. |
| External network | Discovery is opt-in and disabled by default. No automatic enrollment of public peers. |

## Assets

- Head configuration and policy
- Node identity registry and authorization set
- Short-lived admission credentials (HMAC tokens)
- Topology state and audit log

## Threats and Mitigations

### 1. Key / credential compromise
- **Threat**: Stolen token used to impersonate a node.
- **Mitigation**: Short TTL, nonce-based replay protection, immediate revocation, HMAC verification with head secret held only in memory. Tokens never logged or committed.

### 2. Unauthorized enrollment
- **Threat**: Node attempts to join without explicit authorization.
- **Mitigation**: Distinct states (DISCOVERED → AUTHENTICATED → AUTHORIZED → ADMITTED). Admission requires verified credential *and* explicit authorization. Fail closed.

### 3. Replay
- **Threat**: Captured admission request replayed.
- **Mitigation**: Nonce tracking; expired credentials rejected; already-admitted nodes rejected on re-admission.

### 4. Denial of service / uncontrolled growth
- **Threat**: Rapid enrollment exhausts resources.
- **Mitigation**: Configurable `max_nodes`, connection caps, concurrent admission limit, expansion rate limit. Recovery attempts are bounded; loops cannot create new nodes beyond policy.

### 5. Head failure
- **Threat**: Control plane becomes unavailable.
- **Mitigation**: New admissions pause. Existing nodes retain only previously granted local permissions and bounded leases. Recovery validates policy before resuming. No silent privilege escalation.

### 6. Trust propagation
- **Threat**: An admitted node attempts to vouch for another.
- **Mitigation**: Only the head can call `authorize`. No peer-to-peer trust conferral API.

### 7. Policy / configuration error
- **Threat**: Missing or invalid limits.
- **Mitigation**: Configuration validation at construction; fail-closed when policy cannot be verified.

## Out of Scope (current version)

- Multi-head consensus / distributed authority transfer (interfaces reserved; not implemented)
- Hardware-backed key storage
- Real network transport and encryption beyond credential tokens
- Internet-wide discovery or automatic public enrollment

## Residual Risks

- Single-head availability remains a operational concern; multi-head roadmap is documented.
- Simulation uses deterministic fake identities; production must replace with real PKI.
