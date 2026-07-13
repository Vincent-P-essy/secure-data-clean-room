# Secure Data Clean Room benchmark

- Policy expectation accuracy: **100.0%**
- Cases: **14** (4 allow / 10 deny)
- Iterations per case: **20**
- Audit chain valid after run: **true**

| Case | Expected | Actual | p50 | p95 | Reasons |
|---|---:|---:|---:|---:|---|
| allow-department-average | ALLOW | ALLOW | 5.529 ms | 41.337 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| allow-global-count | ALLOW | ALLOW | 2.294 ms | 10.554 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| allow-filtered-performance | ALLOW | ALLOW | 4.330 ms | 9.853 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| allow-approved-in-filter | ALLOW | ALLOW | 2.666 ms | 7.313 ms | AGGREGATE_POLICY_ALLOWED, PARAMETERIZED_QUERY_REBUILT, MINIMUM_GROUP_SIZE_ENFORCED, PRIVACY_RELEASE_APPLIED, STICKY_RELEASE_REUSED |
| deny-direct-identifier | DENY | DENY | 1.203 ms | 2.458 ms | DIRECT_IDENTIFIER |
| deny-raw-sensitive-value | DENY | DENY | 0.962 ms | 1.357 ms | RAW_SENSITIVE_COLUMN |
| deny-wildcard | DENY | DENY | 1.060 ms | 2.415 ms | WILDCARD_FORBIDDEN |
| deny-no-aggregate | DENY | DENY | 1.134 ms | 1.438 ms | AGGREGATE_REQUIRED |
| deny-or-slicing | DENY | DENY | 1.648 ms | 2.746 ms | FILTER_NOT_ALLOWED |
| deny-user-having | DENY | DENY | 1.401 ms | 2.224 ms | UNSUPPORTED_QUERY_SHAPE |
| deny-subquery | DENY | DENY | 1.276 ms | 1.965 ms | UNSUPPORTED_QUERY_SHAPE |
| deny-union | DENY | DENY | 1.386 ms | 1.833 ms | SELECT_ONLY |
| deny-write | DENY | DENY | 0.930 ms | 1.286 ms | SELECT_ONLY |
| deny-unapproved-sum | DENY | DENY | 1.299 ms | 1.580 ms | EXPRESSION_NOT_ALLOWED |

Latencies cover local policy parsing, ledger operations, SQLite execution,
privacy transformation, and audit append. They are not production throughput claims.
