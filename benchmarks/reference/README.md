# Reviewed reference run

This directory preserves one measured run so portfolio readers can inspect a
result without executing the project. It is evidence for a particular local
environment, not a performance promise.

- Date: 2026-07-12
- Python: 3.12.13
- Kernel/platform: Linux 5.15.0-185-generic x86_64, glibc 2.35
- Dataset: 180 deterministic synthetic records generated in a fresh temporary directory
- Corpus: 14 cases, 20 full-service iterations per case
- Result: 14/14 expected decisions, HMAC audit chain valid after 280 entries

`inputs.sha256` binds the policy and adversarial corpus used for the run.
Functional decisions should reproduce with the locked environment. Latency
will vary with storage, scheduling, CPU, virtualization, and runtime versions.
