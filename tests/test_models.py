from __future__ import annotations

import pytest
from pydantic import ValidationError

from secure_data_clean_room.models import (
    FilterPredicate,
    Metric,
    MetricPolicy,
    Principal,
    QueryPlan,
    QueryRequest,
    Role,
)


def test_query_plan_fingerprint_is_stable_and_sensitive_to_filters() -> None:
    first = QueryPlan(
        "workforce-v1",
        ("department",),
        (Metric("avg", "salary", "avg_salary"),),
        (FilterPredicate("region", "eq", ("France",)),),
    )
    same = QueryPlan(
        "workforce-v1",
        ("department",),
        (Metric("avg", "salary", "avg_salary"),),
        (FilterPredicate("region", "eq", ("France",)),),
    )
    different = QueryPlan(
        "workforce-v1",
        ("department",),
        (Metric("avg", "salary", "avg_salary"),),
        (FilterPredicate("region", "eq", ("Spain",)),),
    )
    assert first.fingerprint() == same.fingerprint()
    assert first.fingerprint() != different.fingerprint()
    assert first.canonical_payload()["dataset"] == "workforce-v1"


def test_validation_rejects_invalid_principal_and_request() -> None:
    with pytest.raises(ValidationError):
        Principal(subject="contains spaces", role=Role.ANALYST)
    with pytest.raises(ValidationError):
        QueryRequest(sql="")
    with pytest.raises(ValidationError):
        QueryRequest(sql="SELECT 1", epsilon=0)


def test_metric_bounds_must_increase() -> None:
    with pytest.raises(ValidationError):
        MetricPolicy(column="salary", functions=frozenset({"avg"}), lower=10, upper=5)
