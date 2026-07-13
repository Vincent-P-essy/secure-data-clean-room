from __future__ import annotations

from pathlib import Path

import pytest

from secure_data_clean_room.models import Principal, Role
from secure_data_clean_room.policy import PolicyEngine, PolicyViolation, load_policy


@pytest.fixture
def engine(repository_root: Path) -> PolicyEngine:
    return PolicyEngine(load_policy(repository_root / "fixtures/policy.json"))


def test_compile_rebuilds_parameterized_aggregate(engine: PolicyEngine, analyst: Principal) -> None:
    plan = engine.plan(
        """
        SELECT department, AVG(salary) AS average_salary, COUNT(*) AS people
        FROM employees
        WHERE region IN ('France', 'Germany') AND active = TRUE
        GROUP BY department
        """,
        analyst,
    )
    sql, parameters = engine.compile(plan)
    assert plan.dimensions == ("department",)
    assert [metric.alias for metric in plan.metrics] == ["average_salary", "people"]
    assert "France" not in sql
    assert '"region" IN (?, ?)' in sql
    assert "HAVING COUNT(*) >= ?" in sql
    assert parameters == ["France", "Germany", True, 10, 100]


def test_global_count_is_supported(engine: PolicyEngine, analyst: Principal) -> None:
    plan = engine.plan("SELECT COUNT(*) AS total FROM employees", analyst)
    sql, parameters = engine.compile(plan)
    assert plan.dimensions == ()
    assert "GROUP BY" not in sql
    assert parameters == [10, 100]


def test_inequality_filter_is_compiled(engine: PolicyEngine, analyst: Principal) -> None:
    plan = engine.plan(
        "SELECT region, AVG(salary) FROM employees WHERE active != 0 GROUP BY region",
        analyst,
    )
    sql, parameters = engine.compile(plan)
    assert '"active" != ?' in sql
    assert parameters[0] == 0


@pytest.mark.parametrize(
    ("sql", "code"),
    [
        ("SELECT department FROM employees GROUP BY department", "AGGREGATE_REQUIRED"),
        ("SELECT salary FROM employees", "RAW_SENSITIVE_COLUMN"),
        ("SELECT name FROM employees", "DIRECT_IDENTIFIER"),
        ("SELECT * FROM employees", "WILDCARD_FORBIDDEN"),
        ("SELECT COUNT(salary) FROM employees", "COUNT_ONLY_ROWS"),
        ("SELECT SUM(salary) FROM employees", "EXPRESSION_NOT_ALLOWED"),
        ("SELECT AVG(active) FROM employees", "METRIC_NOT_ALLOWED"),
        (
            "SELECT department AS team, AVG(salary) FROM employees GROUP BY department",
            "DIMENSION_ALIAS_FORBIDDEN",
        ),
        (
            "SELECT department, AVG(salary) FROM employees",
            "INVALID_GROUPING",
        ),
        (
            "SELECT department, AVG(salary) FROM employees GROUP BY region",
            "INVALID_GROUPING",
        ),
        (
            "SELECT department, department, AVG(salary) FROM employees GROUP BY department",
            "DUPLICATE_OUTPUT",
        ),
        (
            "SELECT department, AVG(salary) AS department FROM employees GROUP BY department",
            "DUPLICATE_OUTPUT",
        ),
        (
            "SELECT region, AVG(salary) FROM employees WHERE salary = 50000 GROUP BY region",
            "FILTER_COLUMN_NOT_ALLOWED",
        ),
        (
            "SELECT region, AVG(salary) FROM employees WHERE name = 'Alice' GROUP BY region",
            "DIRECT_IDENTIFIER",
        ),
        (
            "SELECT region, AVG(salary) FROM employees "
            "WHERE department = 'Risk' OR department = 'Finance' GROUP BY region",
            "FILTER_NOT_ALLOWED",
        ),
        (
            "SELECT region, AVG(salary) FROM employees WHERE active > 0 GROUP BY region",
            "FILTER_NOT_ALLOWED",
        ),
        (
            "SELECT region, AVG(salary) FROM employees "
            "WHERE department IN (SELECT department FROM employees) GROUP BY region",
            "UNSUPPORTED_QUERY_SHAPE",
        ),
        (
            "SELECT region, AVG(salary) FROM employees "
            "WHERE department = lower('Risk') GROUP BY region",
            "LITERAL_REQUIRED",
        ),
        ("SELECT AVG(salary) FROM other_table", "DATASET_NOT_ALLOWED"),
        ("SELECT AVG(salary) FROM main.employees", "QUALIFIED_TABLE_FORBIDDEN"),
        ("SELECT AVG(salary) FROM employees LIMIT 1", "UNSUPPORTED_QUERY_SHAPE"),
        ("SELECT DISTINCT AVG(salary) FROM employees", "UNSUPPORTED_QUERY_SHAPE"),
        (
            "SELECT department, AVG(salary) FROM employees GROUP BY department HAVING COUNT(*) = 1",
            "UNSUPPORTED_QUERY_SHAPE",
        ),
        (
            "SELECT a.department, AVG(a.salary) FROM employees a GROUP BY a.department",
            "COLUMN_QUALIFIER",
        ),
        (
            "SELECT department, AVG(salary) FROM employees "
            "JOIN employees b ON b.department = employees.department GROUP BY department",
            "UNSUPPORTED_QUERY_SHAPE",
        ),
        (
            "WITH data AS (SELECT * FROM employees) SELECT AVG(salary) FROM data",
            "UNSUPPORTED_QUERY_SHAPE",
        ),
        (
            "SELECT AVG(salary) FROM (SELECT * FROM employees)",
            "UNSUPPORTED_QUERY_SHAPE",
        ),
        (
            "SELECT department, AVG(salary) FROM employees GROUP BY department "
            "UNION SELECT department, AVG(salary) FROM employees GROUP BY department",
            "SELECT_ONLY",
        ),
        ("UPDATE employees SET salary = 0", "SELECT_ONLY"),
        ("SELECT AVG(salary) FROM employees; SELECT 1", "SELECT_ONLY"),
        ("SELECT FROM", "SQL_PARSE_ERROR"),
    ],
)
def test_denied_query_shapes(engine: PolicyEngine, analyst: Principal, sql: str, code: str) -> None:
    with pytest.raises(PolicyViolation) as captured:
        engine.plan(sql, analyst)
    assert captured.value.code == code


def test_non_analyst_cannot_query(engine: PolicyEngine) -> None:
    with pytest.raises(PolicyViolation) as captured:
        engine.plan(
            "SELECT COUNT(*) FROM employees",
            Principal(subject="unit.auditor", role=Role.AUDITOR),
        )
    assert captured.value.code == "ROLE_CANNOT_QUERY_DATA"


def test_too_many_filters(engine: PolicyEngine, analyst: Principal) -> None:
    sql = (
        "SELECT AVG(salary) FROM employees WHERE active = 1 AND region = 'France' "
        "AND department = 'Risk' AND job_family = 'analyst' AND age_band = '30-39'"
    )
    with pytest.raises(PolicyViolation) as captured:
        engine.plan(sql, analyst)
    assert captured.value.code == "TOO_MANY_FILTERS"


def test_policy_loader_reports_invalid_file(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="cannot load"):
        load_policy(path)
