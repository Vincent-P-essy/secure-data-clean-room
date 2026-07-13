from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from secure_data_clean_room.models import (
    FilterPredicate,
    Metric,
    Principal,
    QueryPlan,
    Role,
)
from secure_data_clean_room.state import BudgetExceeded, DifferencingRisk, StateStore


@pytest.fixture
def store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"audit" * 8)


def test_budget_charges_unique_release_once(store: StateStore) -> None:
    first = store.reserve_budget("analyst", "same", 0.5, 1.0)
    repeated = store.reserve_budget("analyst", "same", 0.5, 1.0)
    second = store.reserve_budget("analyst", "other", 0.5, 1.0)
    assert first.newly_charged is True
    assert repeated.newly_charged is False
    assert repeated.snapshot.spent == 0.5
    assert second.snapshot.remaining == 0
    with pytest.raises(BudgetExceeded):
        store.reserve_budget("analyst", "third", 0.1, 1.0)
    assert store.budget("analyst", 1.0).spent == 1.0


def test_variant_guard_blocks_fifth_distinct_slice(store: StateStore) -> None:
    for index, region in enumerate(("France", "Germany", "Spain", "Italy")):
        plan = QueryPlan(
            "workforce-v1",
            ("department",),
            (Metric("avg", "salary", "avg_salary"),),
            (FilterPredicate("region", "eq", (region,)),),
        )
        store.guard_query_variants("analyst", plan)
        if index == 0:
            store.guard_query_variants("analyst", plan)
    blocked = QueryPlan(
        "workforce-v1",
        ("department",),
        (Metric("avg", "salary", "avg_salary"),),
        (FilterPredicate("region", "eq", ("Belgium",)),),
    )
    with pytest.raises(DifferencingRisk):
        store.guard_query_variants("analyst", blocked)


def test_audit_chain_detects_tampering(store: StateStore) -> None:
    principal = Principal(subject="unit.analyst", role=Role.ANALYST)
    first = store.append_audit(
        principal,
        action="aggregate_query",
        outcome="allowed",
        request_id="request-0001",
        query_hash="a" * 64,
        reason_codes=["ALLOW"],
    )
    second = store.append_audit(
        principal,
        action="aggregate_query",
        outcome="denied",
        request_id="request-0002",
        query_hash="b" * 64,
        reason_codes=["DENY"],
    )
    assert (first, second) == (1, 2)
    assert store.verify_audit().model_dump() == {
        "valid": True,
        "entries_checked": 2,
        "first_invalid_entry": None,
    }

    connection = sqlite3.connect(store.path)
    connection.execute("UPDATE audit_log SET outcome = 'allowed' WHERE id = 2")
    connection.commit()
    connection.close()
    verification = store.verify_audit()
    assert verification.valid is False
    assert verification.first_invalid_entry == 2


def test_state_rejects_weak_audit_key(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="32"):
        StateStore(tmp_path / "state.db", b"weak")
