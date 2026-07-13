from __future__ import annotations

from typing import Any, cast

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


def test_release_fingerprint_canonicalizes_presentation_but_binds_dataset_version() -> None:
    first = QueryPlan(
        "workforce-v1",
        ("department", "region"),
        (Metric("avg", "salary", "first_alias"),),
        (
            FilterPredicate("active", "eq", (True,)),
            FilterPredicate("region", "in", ("France", "Germany")),
        ),
        "2026-07-12",
    )
    equivalent = QueryPlan(
        "workforce-v1",
        ("region", "department"),
        (Metric("avg", "salary", "renamed"),),
        (
            FilterPredicate("region", "in", ("Germany", "France", "France")),
            FilterPredicate("active", "eq", (1,)),
        ),
        "2026-07-12",
    )
    migrated = QueryPlan(
        "workforce-v1",
        equivalent.dimensions,
        equivalent.metrics,
        equivalent.filters,
        "2026-07-13",
    )
    assert first.fingerprint() == equivalent.fingerprint()
    assert first.fingerprint() != migrated.fingerprint()
    assert '"dataset_version":"2026-07-12"' in first.canonical_json()


def test_filter_semantics_reject_non_finite_or_unsupported_scalars() -> None:
    assert FilterPredicate("active", "eq", (None,)).semantic_payload()["values"] == [
        {"type": "null", "value": "null"}
    ]
    with pytest.raises(ValueError, match="finite"):
        FilterPredicate("active", "eq", (float("nan"),)).semantic_payload()
    with pytest.raises(TypeError, match="unsupported"):
        FilterPredicate("active", "eq", (cast(Any, object()),)).semantic_payload()


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
