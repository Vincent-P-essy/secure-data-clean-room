# Secure Data Clean Room benchmark

- Policy expectation accuracy: **100.0%**
- Privacy/control accuracy: **100.0%**
- Cases: **14** (4 allow / 10 deny)
- Control checks: **5**
- Iterations per SQL case: **20**
- Audit chain valid after run: **true**
- Source revision: `ebc49a04f998e9a8b8b3f84c6fe674daa38529ae` (dirty: `true`)
- Source tree SHA-256: `d75965c90bf4d203daf79d3320baba7ec5f7d09032571bdf5636763ea68e9243`

## SQL policy corpus

| Case | Expected | Actual | p50 | p95 | Reasons |
|---|---:|---:|---:|---:|---|
| allow-department-average | ALLOW | ALLOW | 1.444 ms | 3.471 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| allow-global-count | ALLOW | ALLOW | 1.284 ms | 2.348 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| allow-filtered-performance | ALLOW | ALLOW | 1.471 ms | 2.173 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| allow-approved-in-filter | ALLOW | ALLOW | 1.607 ms | 2.364 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| deny-direct-identifier | DENY | DENY | 0.726 ms | 1.029 ms | DIRECT_IDENTIFIER |
| deny-raw-sensitive-value | DENY | DENY | 0.649 ms | 0.872 ms | RAW_SENSITIVE_COLUMN |
| deny-wildcard | DENY | DENY | 0.661 ms | 0.854 ms | WILDCARD_FORBIDDEN |
| deny-no-aggregate | DENY | DENY | 0.697 ms | 1.108 ms | AGGREGATE_REQUIRED |
| deny-or-slicing | DENY | DENY | 1.010 ms | 1.190 ms | FILTER_NOT_ALLOWED |
| deny-user-having | DENY | DENY | 0.770 ms | 0.934 ms | UNSUPPORTED_QUERY_SHAPE |
| deny-subquery | DENY | DENY | 0.732 ms | 0.948 ms | UNSUPPORTED_QUERY_SHAPE |
| deny-union | DENY | DENY | 0.919 ms | 1.280 ms | SELECT_ONLY |
| deny-write | DENY | DENY | 0.581 ms | 0.804 ms | SELECT_ONLY |
| deny-unapproved-sum | DENY | DENY | 0.789 ms | 1.132 ms | EXPRESSION_NOT_ALLOWED |

## Privacy and integrity controls

| Control | Expected | Actual | Evidence |
|---|---:|---:|---|
| sticky-equivalent-release | PASS | PASS | `{"budget_spent":0.5,"same_protected_values":true}` |
| privacy-budget-exhaustion | PASS | PASS | `{"decisions":["ALLOW","ALLOW","ALLOW","ALLOW","ALLOW","DENY"],"last_reason_codes":["PRIVACY_BUDGET_EXHAUSTED"]}` |
| control-plane-roles-denied-data | PASS | PASS | `{"reason_codes":[["ROLE_CANNOT_QUERY_DATA"],["ROLE_CANNOT_QUERY_DATA"]]}` |
| canonical-differencing-guard | PASS | PASS | `{"decisions":["ALLOW","ALLOW","ALLOW","ALLOW","DENY"],"last_reason_codes":["DIFFERENCING_RISK"]}` |
| audit-checkpoint-truncation | PASS | PASS | `{"full_delete_valid":false,"tail_delete_valid":false}` |

Latencies cover local policy parsing, ledger operations, SQLite execution, privacy transformation, and audit append. They are not production throughput claims. `observations.jsonl` preserves every raw response envelope used for the SQL summary; `manifest.sha256` authenticates the generated evidence only after an independent reviewer trusts the repository and signing/distribution channel.
