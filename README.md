# Octopie

Secure, configurable **head architecture** for managing 42 independently authenticated and explicitly authorized nodes, with a tested path to scale beyond 42.

```
DISCOVERED → AUTHENTICATED → AUTHORIZED → ADMITTED
```

Discovery never implies permission to join. Every admission is policy-bounded, explicitly authorized, and auditable.

## Trust Model

| Role | Authority |
|------|-----------|
| **Head** | Configuration, admission policy, orchestration, resource budgets, audit, safe shutdown, revocation |
| **Admitted node** | Only the capability scopes granted at admission; cannot authorize peers |
| **Discovered peer** | Visible, untrusted |

Trust is never propagated automatically from an admitted node to its peers.

## Node Lifecycle States

1. **DISCOVERED** – seen by the head, no credentials verified  
2. **AUTHENTICATED** – credential verified  
3. **AUTHORIZED** – explicitly authorized by the head  
4. **ADMITTED** – capacity and rate limits passed; worker allocated  
5. **DEGRADED / ISOLATED / REVOKED** – health or policy actions

Any failed check prevents admission and records a clear rejection reason (no secrets exposed).

## Quick Start

```bash
# Install (Python ≥ 3.10)
pip install -e ".[dev]"

# Run the full test suite
pytest -v

# Simulate 42 authorized nodes
python -c "
from octopie.simulation import NetworkSimulator
from octopie import HeadConfig
sim = NetworkSimulator(HeadConfig.for_target(42, seed=42))
sim.bootstrap_identities()
print('admitted:', sim.grow_to_target())
print(sim.head.status())
"
```

## Configuration

42 is the **default target**, not a hard-coded maximum. Targets of 8, 16, 32, 42, 64, … are supported purely by configuration.

```python
from octopie import HeadConfig, LimitsConfig

# Default (target 42)
cfg = HeadConfig()

# Explicit larger deployment
cfg = HeadConfig.for_target(64, limits=LimitsConfig(max_nodes=128, max_expansion_per_second=8.0))
```

See `config/example.yaml` for a minimal conservative example (real network expansion disabled).

### Key limits

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `max_nodes` | 42 | Hard capacity ceiling |
| `max_concurrent_admissions` | 8 | Parallel admission slots |
| `max_expansion_per_second` | 4.0 | Rate limit |
| `recovery_max_attempts` | 3 | Bounds recovery loops |
| `shutdown_deadline_seconds` | 30 | Safe shutdown window |

## Credential Lifecycle

- Identities are registered, then **explicitly authorized** by the head.
- Short-lived HMAC tokens are issued; the token itself is never stored in plaintext.
- Nonce tracking rejects replays.
- Revocation is immediate: identity, credentials, topology state, and workers are cleared.

## Head Outage Behaviour

- New admissions **pause** when the control plane is unavailable.
- Existing nodes retain only previously granted local permissions and bounded leases.
- Recovery validates policy before resuming admissions.
- No silent privilege escalation occurs during loss or recovery.

A documented authority-transfer interface is reserved for future multi-head operation; distributed consensus is intentionally **not** implemented in this version.

## Simulation & Tests

```bash
pytest -v --cov=octopie
```

The suite verifies:

- 8 / 16 / 32 / 42 / 64 node targets
- Rejection of unauthenticated, unauthorized, revoked, and replayed credentials
- Capacity and rate limits
- Bounded recovery
- Head-loss pause
- Deterministic reproducibility with a fixed seed
- Audit log redaction

All tests use deterministic fake identities; no real external nodes are required.

## Architecture Modules

| Module | Responsibility |
|--------|----------------|
| `head` | Authority, orchestration, safe shutdown |
| `admission` | Policy gate (authn → authz → capacity → rate) |
| `identity` | Registration, credentials, revocation |
| `topology` | State machine and approved links |
| `health` | Timeouts, bounded recovery |
| `arm` | Worker allocate / pause / replace / retire |
| `limits` | Rate and concurrency enforcement |
| `simulation` | Deterministic growth scenarios |
| `audit` | Redacted event log |

## Security Notes

- Uses the established `cryptography` / `hmac` / `hashlib` libraries; no invented primitives.
- Private keys, tokens, and credentials are **never** committed, logged, or placed in test fixtures.
- Network discovery stays opt-in and disabled by default.
- See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for trust boundaries and mitigations.

## Roadmap (multi-head)

1. Stable interfaces for authority transfer (already sketched).
2. Lease renewal protocol for admitted nodes.
3. Optional multi-head coordination **after** single-head behaviour is production-hardened.
4. Hardware-backed identity store.

## License

MIT
