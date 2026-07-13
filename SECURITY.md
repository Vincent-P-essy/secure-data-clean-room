# Security policy

## Supported versions

Security fixes are applied to the latest commit on `main`. This repository is a
demonstrator and does not publish a long-term-support release line.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting feature for this repository. Do
not open a public issue containing an exploit, API key, sensitive query, or
dataset. Include the affected commit, preconditions, minimal reproduction, and
the security property that fails.

Expect acknowledgement within seven days. No bounty or response SLA is
promised. Please do not test against systems or data you do not own.

## Lab safety

- The committed dataset is synthetic and contains no real identity.
- `CLEAN_ROOM_DEMO_MODE=1` activates public demo keys and deterministic secrets.
  It must never be set in a real deployment.
- The dashboard binds to loopback in the documented local workflow.
- Never import production data into this prototype. It lacks the operational,
  legal, retention, deletion, key-management, and assurance controls required
  for that use.
