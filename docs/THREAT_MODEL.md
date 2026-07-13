# Threat model

## Scope

The protected assets are raw records, direct identifiers, sensitive numeric
measures, privacy budget, policy configuration, secret keys, and audit history.
The main adversary is an authenticated analyst attempting to recover an
individual value through syntax bypass, small groups, repeated queries, or
resource exhaustion. Compromised administrators and host-level attackers are
important residual risks but are not solved by this single service.

## Trust boundaries

1. Browser or CLI to API: request, principal, and SQL are untrusted.
2. API to policy engine: policy configuration and application code are trusted.
3. Compiler to dataset: only compiler-generated SQL should cross this boundary.
4. Service to state database: ledger and audit integrity depend on the HMAC key.
5. Container to host: the host and container runtime remain trusted.

## Threats and controls

| Threat | Primary controls | Residual risk |
|---|---|---|
| Direct row extraction | aggregate-only projections; forbidden identifiers; no wildcard | policy mistakes can expose a newly added column |
| SQL injection | AST reduction; compiler-owned identifiers; bound literals | parser or compiler vulnerability |
| Bypass through joins, CTEs, subqueries, unions, windows | fail-closed unsupported-shape list and adversarial tests | a new AST node needs explicit review |
| Small-group disclosure | compiler-added `HAVING COUNT(*) >= 10`; pre-release group check | group membership can still be inferred from public context |
| Repeated-query averaging | sticky noise; unique-release ledger | changed but equivalent query forms may consume budget before detection |
| Differencing / slicing | four-variant limit per plan shape per 24 hours; filter allowlist | heuristic can miss semantically equivalent shapes and cause false refusals |
| Unbounded numeric contribution | policy bounds; synthetic fixture constraints; output clamp | a real ingestion pipeline must enforce clipping before storage |
| Budget race | `BEGIN IMMEDIATE` transaction and unique release key | single-node SQLite limits throughput |
| Audit deletion or editing | previous-hash chain plus HMAC; full-chain verifier | attacker with key and database access can rewrite history; no external checkpoint |
| Denial of service | SQL subset; step, time, result, memory, PID and CPU limits | concurrent request admission control is not implemented |
| Stolen API key | role separation; no-store responses; loopback demo bind | static keys lack expiry, device binding, and revocation workflow |
| Secret disclosure in logs | audit stores query digest and reason codes, not SQL | framework or infrastructure logs require separate review |

## Explicit non-goals

- Hosting real personal, banking, health, or regulated data.
- Formal proof of differential privacy for arbitrary adaptive workloads.
- Protecting data after endpoint compromise or screenshots by an authorized analyst.
- Defending against a malicious host administrator.
- Providing secure multi-party computation, trusted execution environments, or
  homomorphic encryption.
