# Reviewed reference run

This directory preserves one measured run so portfolio readers can inspect a
result without executing the project. It is evidence for a particular local
environment, not a performance promise.

- Date: 2026-07-13
- Python: 3.12.13
- Kernel/platform: Linux 5.15.0-185-generic x86_64, glibc 2.35
- Dataset: 180 deterministic synthetic records generated in a fresh temporary directory
- Corpus: 14 cases, 20 full-service iterations per case
- Controls: sticky semantic release, budget exhaustion, roles, canonical differencing,
  and local audit-head truncation detection
- Result: 14/14 expected decisions, 5/5 control checks, primary HMAC audit chain
  valid after 295 entries

`inputs.sha256` binds the policy, corpus, lockfile and benchmark runner.
`benchmark.json` retains environment and source metadata, while
`observations.jsonl` retains every response envelope behind the SQL summary.
`manifest.sha256` covers every generated artifact. The run records a clean source
revision together with a hash of the relevant source tree; the latter remains the
portable identity if the reviewed branch is later squash-merged. These hashes
provide integrity, not authorship or trusted timestamping.

Functional decisions should reproduce with the locked environment. Latency will
vary with storage, scheduling, CPU, virtualization, and runtime versions.
