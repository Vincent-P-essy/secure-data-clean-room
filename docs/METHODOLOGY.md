# Experimental methodology

## Questions

The versioned experiment answers four narrow questions:

1. Does the policy accept intended aggregate queries?
2. Does it reject representative extraction and syntax-bypass requests?
3. Do sticky releases, budget exhaustion, role separation and canonical slicing
   controls behave as declared?
4. Does the authenticated local audit head detect suffix and full-log truncation?

It does not estimate privacy loss on a real population or benchmark production
concurrency.

## Dataset

`clean-room init-demo` creates 180 deterministic synthetic records distributed
across six departments, three regions, four job families, and four age bands.
Subject tokens are HMACs over synthetic sequence identifiers. Salaries and
performance values are generated from a fixed pseudo-random seed and constrained
to the policy bounds. No generated row is committed; the procedure is the source
of truth.

## Adversarial corpus

`fixtures/corpus/queries.json` contains positive and negative controls. Negative
cases include direct identifiers, raw measures, wildcard projection, missing
aggregation, `OR` slicing, user-controlled `HAVING`, subqueries, unions, writes,
and an unapproved aggregate. Each case declares `ALLOW` or `DENY` before execution.

Expectation accuracy is:

```text
cases whose every repeated decision equals the declared decision / all cases
```

This is policy conformance on a curated corpus, not a false-positive rate over
real analyst workloads and not proof that every SQL bypass is covered.

## Privacy and integrity controls

After the SQL corpus, the benchmark executes five deterministic checks:

1. the same statistic with presentation-only alias/order changes returns the same
   protected values and is charged once;
2. five unique epsilon-1 releases consume the configured budget and the sixth is denied;
3. auditor and privacy-officer principals cannot query data;
4. alias changes do not reset the four-variant differencing limit;
5. deleting the last audit row and then all audit rows both fail verification while
   the authenticated local checkpoint remains.

These checks establish implementation conformance, not a formal differential-privacy
proof or an external append-only audit guarantee. Audit truncation is exercised in a
separate temporary ledger so corruption does not invalidate the benchmark's primary log.

## Timing

Per-request SQL latency starts immediately before policy evaluation and ends after
the audit append. It includes:

- AST parsing and plan construction;
- query-variant and privacy-ledger transactions;
- local SQLite aggregate execution;
- privacy transformation;
- audit-chain append.

It excludes HTTP transport, browser rendering, container startup, key retrieval,
networked storage, and external identity. The benchmark reports interpolated p50
and p95 values for each case and records Python/platform metadata. Timing is not
used as a CI threshold.

## Reproduction

```bash
export CLEAN_ROOM_DEMO_MODE=1
uv sync --frozen --all-extras
make test
make benchmark
sha256sum fixtures/corpus/queries.json fixtures/policy.json
```

CI uses the lockfile, checks formatting and strict typing, enforces at least 90%
branch-aware test coverage, executes the benchmark, validates Compose, and
builds and smoke-tests both the wheel and container. Functional or control
mismatches make the benchmark command non-zero.

## Evidence and provenance

Each run emits:

- `benchmark.json`: schema-versioned summary, environment, Git revision/dirty state,
  source-tree hash, lockfile hash and benchmark-runner hash;
- `observations.jsonl`: every unaggregated response envelope used to calculate the SQL
  decision and latency summaries;
- `summary.csv` and `controls.csv`: review-friendly projections;
- `REPORT.md`: human-readable interpretation;
- `inputs.sha256`: corpus, policy, lockfile and runner hashes;
- `manifest.sha256`: hashes of every generated evidence file except the manifest itself.

The manifest is an integrity check, not a signature. A reviewer must obtain it through a
trusted repository or signing channel. A run from an uncommitted worktree records
`dirty=true` and is additionally bound to the complete relevant source-tree hash.

## Interpreting the privacy output

The implementation uses Laplace noise calibrated to a declared bound and actual
released group size. Epsilon is divided across selected metrics. Noise is derived
with HMAC from the protected release fingerprint and group, so identical retries
return an identical value and are charged once. Presentation-only aliases and ordering
are canonicalized. Dataset version and epsilon are bound into the release identity, so a
new dataset version or epsilon creates a new charged release.

This sticky construction is practical for demonstrating averaging resistance,
but the service does not claim a formal privacy guarantee for arbitrary adaptive
queries. See the threat model for residual attacks.
