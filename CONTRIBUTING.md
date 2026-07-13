# Contributing

Changes should preserve the central invariant: untrusted SQL is parsed into a
typed allowlisted plan and never executed directly.

## Local checks

```bash
uv sync --frozen --all-extras
make lint
make test
make benchmark
docker compose config --quiet
docker build -t secure-data-clean-room:test .
```

Every policy change needs:

1. a positive test showing the intended aggregate;
2. at least one adversarial negative test for a plausible bypass;
3. an update to `fixtures/corpus/queries.json` when the public contract changes;
4. a threat-model or methodology update when a trust boundary changes.

Generated benchmark timings must include their environment and must not replace
the reviewed reference snapshot without an explanation. Never add real personal
data, production credentials, or a claim of formal differential privacy.

Use focused commits and the repository's configured author identity. Do not add
automated co-author trailers.
