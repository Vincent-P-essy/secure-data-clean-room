from __future__ import annotations

import hashlib
import time
import uuid

from .database import DatasetExecutionError, ReadOnlyDataset, initialize_demo_dataset
from .models import (
    Decision,
    ExplainResponse,
    Principal,
    PrivacyMetadata,
    QueryRequest,
    QueryResponse,
)
from .policy import PolicyEngine, PolicyViolation, load_policy
from .privacy import PrivacyMechanism
from .settings import Settings
from .state import BudgetExceeded, DifferencingRisk, StateStore


class CleanRoomService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.policy = load_policy(settings.policy_path)
        self.engine = PolicyEngine(self.policy)
        self.dataset = ReadOnlyDataset(settings.dataset_path, self.policy)
        self.state = StateStore(settings.state_path, settings.audit_key)
        self.privacy = PrivacyMechanism(self.policy, settings.noise_key)

    def initialize_demo(self, *, rows: int = 180) -> None:
        initialize_demo_dataset(self.settings.dataset_path, self.settings.pseudonym_key, rows=rows)

    def query(self, request: QueryRequest, principal: Principal) -> QueryResponse:
        started = time.perf_counter()
        request_id = request.request_id or f"req-{uuid.uuid4().hex}"
        raw_hash = hashlib.sha256(request.sql.encode()).hexdigest()
        try:
            plan = self.engine.plan(request.sql, principal)
            epsilon = request.epsilon or self.policy.default_epsilon
            if epsilon > self.policy.max_epsilon_per_query:
                raise PolicyViolation(
                    "EPSILON_TOO_LARGE",
                    f"epsilon exceeds per-query maximum {self.policy.max_epsilon_per_query}",
                )
            self.state.guard_query_variants(principal.subject, plan)
            release_fingerprint = hashlib.sha256(
                f"{plan.fingerprint()}\0{epsilon:.12g}".encode()
            ).hexdigest()
            reservation = self.state.reserve_budget(
                principal.subject,
                plan.dataset_version,
                release_fingerprint,
                epsilon,
                self.policy.principal_budget,
            )
            execution = self.dataset.execute(plan)
            protected = self.privacy.protect(
                execution.rows, plan, epsilon, release_fingerprint=release_fingerprint
            )
            reasons = [
                "AGGREGATE_POLICY_ALLOWED",
                "PARAMETERIZED_QUERY_REBUILT",
                "MINIMUM_GROUP_SIZE_ENFORCED",
                "PRIVACY_RELEASE_APPLIED",
            ]
            if not reservation.newly_charged:
                reasons.append("STICKY_RELEASE_REUSED")
            audit_id = self.state.append_audit(
                principal,
                action="aggregate_query",
                outcome="allowed",
                request_id=request_id,
                query_hash=raw_hash,
                reason_codes=reasons,
            )
            return QueryResponse(
                request_id=request_id,
                decision=Decision.ALLOW,
                reason_codes=reasons,
                canonical_query=execution.sql,
                columns=[*plan.dimensions, *(metric.alias for metric in plan.metrics)],
                rows=protected.rows,
                privacy=PrivacyMetadata(
                    mechanism=protected.mechanism,
                    epsilon=epsilon,
                    budget_spent=reservation.snapshot.spent,
                    budget_remaining=reservation.snapshot.remaining,
                    sticky_noise=True,
                    minimum_group_size=self.policy.min_group_size,
                    suppressed_groups=None,
                ),
                audit_entry_id=audit_id,
                elapsed_ms=round((time.perf_counter() - started) * 1_000, 3),
            )
        except (PolicyViolation, DifferencingRisk, BudgetExceeded, DatasetExecutionError) as error:
            code = _error_code(error)
            audit_id = self.state.append_audit(
                principal,
                action="aggregate_query",
                outcome="denied",
                request_id=request_id,
                query_hash=raw_hash,
                reason_codes=[code],
            )
            return QueryResponse(
                request_id=request_id,
                decision=Decision.DENY,
                reason_codes=[code],
                audit_entry_id=audit_id,
                elapsed_ms=round((time.perf_counter() - started) * 1_000, 3),
            )

    def explain(self, request: QueryRequest, principal: Principal) -> ExplainResponse:
        try:
            plan = self.engine.plan(request.sql, principal)
            sql, parameters = self.engine.compile(plan)
            return ExplainResponse(
                decision=Decision.ALLOW,
                reason_codes=[
                    "AGGREGATE_POLICY_ALLOWED",
                    "PARAMETERIZED_QUERY_REBUILT",
                    "MINIMUM_GROUP_SIZE_ENFORCED",
                ],
                canonical_plan=plan.canonical_payload(),
                rewritten_sql=sql,
                parameters=parameters,
            )
        except PolicyViolation as error:
            return ExplainResponse(decision=Decision.DENY, reason_codes=[error.code])


def _error_code(error: Exception) -> str:
    if isinstance(error, PolicyViolation):
        return error.code
    if isinstance(error, DifferencingRisk):
        return "DIFFERENCING_RISK"
    if isinstance(error, BudgetExceeded):
        return "PRIVACY_BUDGET_EXHAUSTED"
    return "DATASET_EXECUTION_FAILED"
