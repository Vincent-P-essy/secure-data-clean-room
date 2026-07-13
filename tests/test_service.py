from __future__ import annotations

import json
from dataclasses import replace

from secure_data_clean_room.models import Decision, Principal, QueryRequest, Role
from secure_data_clean_room.service import CleanRoomService
from secure_data_clean_room.settings import Settings


def test_allowed_query_returns_only_protected_aggregates(
    service: CleanRoomService, analyst: Principal
) -> None:
    request = QueryRequest(
        sql="SELECT department, AVG(salary) AS avg_salary, COUNT(*) AS people "
        "FROM employees GROUP BY department",
        request_id="request-allow-0001",
    )
    first = service.query(request, analyst)
    repeated = service.query(request, analyst)
    assert first.decision is Decision.ALLOW
    assert first.rows == repeated.rows
    assert first.columns == ["department", "avg_salary", "people"]
    assert len(first.rows) == 6
    assert all(set(row) == set(first.columns) for row in first.rows)
    assert repeated.privacy is not None and repeated.privacy.budget_spent == 0.5
    assert "STICKY_RELEASE_REUSED" in repeated.reason_codes
    assert service.state.verify_audit().entries_checked == 2


def test_denials_are_audited(service: CleanRoomService, analyst: Principal) -> None:
    raw = service.query(QueryRequest(sql="SELECT salary FROM employees"), analyst)
    too_much = service.query(QueryRequest(sql="SELECT COUNT(*) FROM employees", epsilon=2), analyst)
    assert raw.decision is Decision.DENY
    assert raw.reason_codes == ["RAW_SENSITIVE_COLUMN"]
    assert too_much.reason_codes == ["EPSILON_TOO_LARGE"]
    assert service.state.verify_audit().entries_checked == 2


def test_budget_exhaustion_is_a_decision(service: CleanRoomService, analyst: Principal) -> None:
    queries = [
        "SELECT COUNT(*) AS total FROM employees",
        "SELECT department, COUNT(*) AS total FROM employees GROUP BY department",
        "SELECT region, COUNT(*) AS total FROM employees GROUP BY region",
        "SELECT job_family, COUNT(*) AS total FROM employees GROUP BY job_family",
        "SELECT age_band, COUNT(*) AS total FROM employees GROUP BY age_band",
    ]
    for index, sql in enumerate(queries):
        result = service.query(
            QueryRequest(sql=sql, epsilon=1, request_id=f"budget-{index:03d}"), analyst
        )
        assert result.decision is Decision.ALLOW
    denied = service.query(
        QueryRequest(
            sql="SELECT active, COUNT(*) AS total FROM employees GROUP BY active",
            epsilon=1,
            request_id="budget-denied",
        ),
        analyst,
    )
    assert denied.decision is Decision.DENY
    assert denied.reason_codes == ["PRIVACY_BUDGET_EXHAUSTED"]


def test_control_role_is_denied_data(service: CleanRoomService) -> None:
    auditor = Principal(subject="unit.auditor", role=Role.AUDITOR)
    response = service.query(QueryRequest(sql="SELECT COUNT(*) FROM employees"), auditor)
    assert response.decision is Decision.DENY
    assert response.reason_codes == ["ROLE_CANNOT_QUERY_DATA"]


def test_explain_has_no_ledger_side_effect(service: CleanRoomService, analyst: Principal) -> None:
    allowed = service.explain(
        QueryRequest(sql="SELECT department, AVG(salary) FROM employees GROUP BY department"),
        analyst,
    )
    denied = service.explain(QueryRequest(sql="SELECT salary FROM employees"), analyst)
    assert allowed.decision is Decision.ALLOW
    assert "France" not in (allowed.rewritten_sql or "")
    assert denied.decision is Decision.DENY
    assert service.state.budget(analyst.subject, service.policy.principal_budget).spent == 0
    assert service.state.verify_audit().entries_checked == 0


def test_equivalent_alias_release_reuses_budget_and_noise(
    service: CleanRoomService, analyst: Principal
) -> None:
    first = service.query(
        QueryRequest(
            sql="SELECT department, AVG(salary) AS first FROM employees GROUP BY department"
        ),
        analyst,
    )
    renamed = service.query(
        QueryRequest(
            sql="SELECT AVG(salary) AS renamed, department FROM employees GROUP BY department"
        ),
        analyst,
    )
    assert first.decision is Decision.ALLOW and renamed.decision is Decision.ALLOW
    first_values = {row["department"]: row["first"] for row in first.rows}
    renamed_values = {row["department"]: row["renamed"] for row in renamed.rows}
    assert first_values == renamed_values
    assert renamed.privacy is not None and renamed.privacy.budget_spent == 0.5
    assert "STICKY_RELEASE_REUSED" in renamed.reason_codes


def test_dataset_version_migration_creates_a_new_budgeted_release(
    settings: Settings, analyst: Principal
) -> None:
    payload = json.loads(settings.policy_path.read_text(encoding="utf-8"))
    policy_path = settings.state_path.parent / "versioned-policy.json"
    policy_path.write_text(json.dumps(payload), encoding="utf-8")
    version_one = CleanRoomService(replace(settings, policy_path=policy_path))
    version_one.initialize_demo()
    query = QueryRequest(sql="SELECT COUNT(*) AS total FROM employees")
    first = version_one.query(query, analyst)

    payload["dataset_version"] = "2026-07-13"
    policy_path.write_text(json.dumps(payload), encoding="utf-8")
    version_two = CleanRoomService(replace(settings, policy_path=policy_path))
    second = version_two.query(query, analyst)

    assert first.privacy is not None and first.privacy.budget_spent == 0.5
    assert second.privacy is not None and second.privacy.budget_spent == 1.0
    assert "STICKY_RELEASE_REUSED" not in second.reason_codes
