# Architecture

## Goal and invariant

The system demonstrates how an analyst can receive useful aggregate statistics
without receiving stored records. Its primary invariant is stronger than
"validate then execute": the submitted SQL is **never** sent to the database.
Only a new statement compiled from a typed, allowlisted plan may cross the data
boundary.

## Components

| Component | Responsibility | Trusted input |
|---|---|---|
| API / CLI | identity context, validation, response envelope | principal mapping and configuration |
| SQL policy engine | parse AST, reject unsupported syntax, build `QueryPlan` | versioned dataset policy |
| trusted compiler | emit identifiers from policy and bind all literal values | typed `QueryPlan` only |
| read-only executor | enforce immutable connection, authorizer, timeout, step and row limits | compiler output only |
| variant guard | limit repeated slicing with changed predicates | canonical plan fingerprints |
| privacy ledger | account unique `(plan, epsilon)` releases per principal | configured budget |
| privacy mechanism | enforce release threshold and perturb bounded metrics | secret noise key and bounds |
| audit chain | record identities, hashes, decisions, and controls | protected HMAC key |

## Query state transition

```text
RECEIVED
   │ parse exactly one SELECT
   ▼
STRUCTURALLY_VALID
   │ reduce projections, grouping, filters
   ▼
POLICY_PLANNED
   │ variant guard + reserve epsilon
   ▼
BUDGETED
   │ compile parameterized SQL + execute read-only
   ▼
AGGREGATED
   │ k-threshold + bounded sticky noise
   ▼
RELEASED ──► append HMAC-linked audit record

Any failed transition ──► DENIED ──► append reason code to audit chain
```

Budget is reserved before reading the aggregate. If execution subsequently
fails, the conservative ledger does not refund the release automatically.
Refund workflows are intentionally absent because they would need an audited
operator decision and proof that no output escaped.

## Data stores

The demonstration separates two SQLite files:

- `workforce.db` is opened with `mode=ro&immutable=1`. It contains HMAC-derived
  subject tokens, approved dimensions, and bounded numeric measures. It stores
  neither names nor emails.
- `state.db` is writable and contains the privacy-spend ledger, short-lived
  query-shape history, and HMAC-linked audit records. Raw SQL and filter values
  are not copied into the audit log; only a SHA-256 query digest is retained.

SQLite's authorizer callback permits only reads of the configured table and
columns and the `AVG`/`COUNT` functions. This is defense in depth because the
compiler already emits the only statement that reaches it.

## Identity boundary

The API maps opaque demo tokens to one of three roles:

- `analyst`: may submit or explain aggregate queries and see their own budget;
- `privacy_officer`: may inspect control health and audit integrity, but not data;
- `auditor`: may verify the audit chain, but not data.

API keys make the boundary visible and testable, but a production design would
replace them with workload identity or OIDC, external policy, short-lived
credentials, key rotation, and independently stored audit checkpoints.

## Deployment boundary

The container runs as UID/GID 65532, drops every Linux capability, requests
`no-new-privileges`, uses a read-only root filesystem, and receives a writable
named volume only at `/data`. It binds the host port to loopback. These controls
reduce impact; they do not create tenant-grade isolation.
