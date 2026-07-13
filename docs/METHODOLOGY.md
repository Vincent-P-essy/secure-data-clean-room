# Experimental methodology

## Questions

The versioned experiment answers three narrow questions:

1. Does the policy accept intended aggregate queries?
2. Does it reject representative extraction and syntax-bypass requests?
3. Does every decision leave a verifiable audit-chain entry?

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

## Timing

Per-request latency starts immediately before policy evaluation and ends after
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
builds the container. Functional mismatches make the benchmark command non-zero.

## Interpreting the privacy output

The implementation uses Laplace noise calibrated to a declared bound and actual
released group size. Epsilon is divided across selected metrics. Noise is derived
with HMAC from the protected release fingerprint and group, so identical retries
return an identical value and are charged once. Different epsilon values create
different fingerprints and consume new budget.

This sticky construction is practical for demonstrating averaging resistance,
but the service does not claim a formal privacy guarantee for arbitrary adaptive
queries. See the threat model for residual attacks.
