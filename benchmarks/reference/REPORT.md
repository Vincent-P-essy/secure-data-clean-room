# Secure Data Clean Room benchmark

- Policy expectation accuracy: **100.0%**
- Privacy/control accuracy: **100.0%**
- Cases: **14** (4 allow / 10 deny)
- Control checks: **5**
- Iterations per SQL case: **20**
- Audit chain valid after run: **true**
- Source revision: `d278292cfadb09405ccaf12cf3da320239f42a19` (dirty: `false`)
- Source tree SHA-256: `d75965c90bf4d203daf79d3320baba7ec5f7d09032571bdf5636763ea68e9243`

## SQL policy corpus

| Case | Expected | Actual | p50 | p95 | Reasons |
|---|---:|---:|---:|---:|---|
| allow-department-average | ALLOW | ALLOW | 1.509 ms | 3.749 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| allow-global-count | ALLOW | ALLOW | 1.252 ms | 1.713 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| allow-filtered-performance | ALLOW | ALLOW | 1.901 ms | 2.886 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| allow-approved-in-filter | ALLOW | ALLOW | 1.563 ms | 2.570 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| deny-direct-identifier | DENY | DENY | 0.746 ms | 1.152 ms | DIRECT_IDENTIFIER |
| deny-raw-sensitive-value | DENY | DENY | 0.661 ms | 0.925 ms | RAW_SENSITIVE_COLUMN |
| deny-wildcard | DENY | DENY | 0.841 ms | 3.654 ms | WILDCARD_FORBIDDEN |
| deny-no-aggregate | DENY | DENY | 1.211 ms | 1.739 ms | AGGREGATE_REQUIRED |
| deny-or-slicing | DENY | DENY | 1.010 ms | 1.442 ms | FILTER_NOT_ALLOWED |
| deny-user-having | DENY | DENY | 0.821 ms | 1.013 ms | UNSUPPORTED_QUERY_SHAPE |
| deny-subquery | DENY | DENY | 0.802 ms | 1.009 ms | UNSUPPORTED_QUERY_SHAPE |
| deny-union | DENY | DENY | 0.685 ms | 0.927 ms | SELECT_ONLY |
| deny-write | DENY | DENY | 0.637 ms | 0.880 ms | SELECT_ONLY |
| deny-unapproved-sum | DENY | DENY | 0.839 ms | 0.984 ms | EXPRESSION_NOT_ALLOWED |

## Privacy and integrity controls

| Control | Expected | Actual | Evidence |
|---|---:|---:|---|
| sticky-equivalent-release | PASS | PASS | `{"budget_spent":0.5,"same_protected_values":true}` |
| privacy-budget-exhaustion | PASS | PASS | `{"decisions":["ALLOW","ALLOW","ALLOW","ALLOW","ALLOW","DENY"],"last_reason_codes":["PRIVACY_BUDGET_EXHAUSTED"]}` |
| control-plane-roles-denied-data | PASS | PASS | `{"reason_codes":[["ROLE_CANNOT_QUERY_DATA"],["ROLE_CANNOT_QUERY_DATA"]]}` |
| canonical-differencing-guard | PASS | PASS | `{"decisions":["ALLOW","ALLOW","ALLOW","ALLOW","DENY"],"last_reason_codes":["DIFFERENCING_RISK"]}` |
| audit-checkpoint-truncation | PASS | PASS | `{"full_delete_valid":false,"tail_delete_valid":false}` |

Latencies cover local policy parsing, ledger operations, SQLite execution, privacy transformation, and audit append. They are not production throughput claims. `observations.jsonl` preserves every raw response envelope used for the SQL summary; `manifest.sha256` authenticates the generated evidence only after an independent reviewer trusts the repository and signing/distribution channel.
