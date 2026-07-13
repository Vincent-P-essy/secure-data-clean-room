# ADR 001: Compile a constrained SQL subset

- Status: accepted
- Date: 2026-07-12

## Context

Executing an analyst statement after keyword filtering or even AST validation
leaves a broad and evolving attack surface. A general SQL engine supports joins,
subqueries, user functions, metadata access, and expressions that are difficult
to reason about as a privacy policy.

## Decision

Accept SQL only as an analyst-facing notation. Parse it, extract a small typed
plan, discard the source statement, and compile a new parameterized query from
policy-controlled identifiers. Fail closed for unsupported syntax.

## Consequences

The execution boundary is small and testable, and filter literals cannot alter
syntax. The cost is compatibility: many legitimate analytical queries are
refused, and every grammar expansion needs new policy logic, adversarial tests,
and a threat-model review. This is an intentional security/usability trade-off.
