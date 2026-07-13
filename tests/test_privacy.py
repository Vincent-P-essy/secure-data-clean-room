from __future__ import annotations

import pytest

from secure_data_clean_room.models import DatasetPolicy, Metric, QueryPlan
from secure_data_clean_room.privacy import PrivacyMechanism


def test_privacy_release_is_sticky_bounded_and_hides_group_size(
    service: object,
) -> None:
    policy: DatasetPolicy = service.policy  # type: ignore[attr-defined]
    mechanism = PrivacyMechanism(policy, b"n" * 32)
    plan = QueryPlan(
        dataset=policy.dataset,
        dimensions=("department",),
        metrics=(
            Metric("avg", "salary", "avg_salary"),
            Metric("count", None, "employees"),
        ),
        filters=(),
    )
    raw = [
        {
            "department": "Risk",
            "avg_salary": 100_000.0,
            "employees": 30,
            "__group_size": 30,
        }
    ]
    first = mechanism.protect(raw, plan, 1.0, "release-a")
    repeated = mechanism.protect(raw, plan, 1.0, "release-a")
    changed = mechanism.protect(raw, plan, 1.0, "release-b")
    assert first.rows == repeated.rows
    assert first.rows != changed.rows
    assert "__group_size" not in first.rows[0]
    assert 25_000 <= float(first.rows[0]["avg_salary"] or 0) <= 250_000
    assert float(first.rows[0]["employees"] or 0) >= 0


def test_small_group_is_suppressed(service: object) -> None:
    policy: DatasetPolicy = service.policy  # type: ignore[attr-defined]
    mechanism = PrivacyMechanism(policy, b"n" * 32)
    plan = QueryPlan(policy.dataset, (), (Metric("count", None, "count"),), ())
    result = mechanism.protect([{"count": 4, "__group_size": 4}], plan, 1.0, "small-release")
    assert result.rows == []


def test_privacy_keys_and_metric_bounds_are_required(service: object) -> None:
    policy: DatasetPolicy = service.policy  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="32"):
        PrivacyMechanism(policy, b"weak")
