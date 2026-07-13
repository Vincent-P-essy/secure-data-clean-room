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
from secure_data_clean_room.state import (
    AuditIntegrityError,
    BudgetExceeded,
    DifferencingRisk,
    StateStore,
)


@pytest.fixture
def store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"audit" * 8)


def test_budget_charges_unique_release_once(store: StateStore) -> None:
    first = store.reserve_budget("analyst", "dataset-v1", "same", 0.5, 1.0)
    repeated = store.reserve_budget("analyst", "dataset-v1", "same", 0.5, 1.0)
    second = store.reserve_budget("analyst", "dataset-v2", "other", 0.5, 1.0)
    assert first.newly_charged is True
    assert repeated.newly_charged is False
    assert repeated.snapshot.spent == 0.5
    assert second.snapshot.remaining == 0
    with pytest.raises(BudgetExceeded):
        store.reserve_budget("analyst", "dataset-v2", "third", 0.1, 1.0)
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


def test_variant_guard_canonicalizes_alias_dimension_and_filter_order(store: StateStore) -> None:
    regions = ("France", "Germany", "Spain", "Italy")
    for index, region in enumerate(regions):
        plan = QueryPlan(
            "workforce-v1",
            ("department", "job_family") if index % 2 == 0 else ("job_family", "department"),
            (Metric("avg", "salary", f"alias_{index}"),),
            (
                FilterPredicate("region", "eq", (region,)),
                FilterPredicate("active", "eq", (bool(index % 2),)),
            )
            if index % 2 == 0
            else (
                FilterPredicate("active", "eq", (int(bool(index % 2)),)),
                FilterPredicate("region", "eq", (region,)),
            ),
            "2026-07-12",
        )
        store.guard_query_variants("canonical.analyst", plan)

    blocked = QueryPlan(
        "workforce-v1",
        ("department", "job_family"),
        (Metric("avg", "salary", "another_alias"),),
        (
            FilterPredicate("region", "eq", ("Belgium",)),
            FilterPredicate("active", "eq", (False,)),
        ),
        "2026-07-12",
    )
    with pytest.raises(DifferencingRisk):
        store.guard_query_variants("canonical.analyst", blocked)


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


@pytest.mark.parametrize(
    "delete_sql", ["DELETE FROM audit_log WHERE id = 2", "DELETE FROM audit_log"]
)
def test_audit_checkpoint_detects_truncation(store: StateStore, delete_sql: str) -> None:
    principal = Principal(subject="unit.analyst", role=Role.ANALYST)
    for index in (1, 2):
        store.append_audit(
            principal,
            action="aggregate_query",
            outcome="allowed",
            request_id=f"request-{index:04d}",
            query_hash=str(index) * 64,
            reason_codes=["ALLOW"],
        )
    with sqlite3.connect(store.path) as connection:
        connection.execute(delete_sql)
    assert store.verify_audit().valid is False
    with pytest.raises(AuditIntegrityError, match="does not match"):
        store.append_audit(
            principal,
            action="aggregate_query",
            outcome="allowed",
            request_id="request-0003",
            query_hash="3" * 64,
            reason_codes=["ALLOW"],
        )


def test_audit_verifier_fails_closed_on_corrupt_reason_payload(store: StateStore) -> None:
    principal = Principal(subject="unit.analyst", role=Role.ANALYST)
    store.append_audit(
        principal,
        action="aggregate_query",
        outcome="allowed",
        request_id="request-0001",
        query_hash="a" * 64,
        reason_codes=["ALLOW"],
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE audit_log SET reason_codes = 'not-json' WHERE id = 1")
    assert store.verify_audit().model_dump() == {
        "valid": False,
        "entries_checked": 0,
        "first_invalid_entry": 1,
    }


def test_missing_or_corrupt_local_checkpoint_fails_closed(store: StateStore) -> None:
    principal = Principal(subject="unit.analyst", role=Role.ANALYST)
    store.append_audit(
        principal,
        action="aggregate_query",
        outcome="allowed",
        request_id="request-0001",
        query_hash="a" * 64,
        reason_codes=["ALLOW"],
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE audit_checkpoint SET checkpoint_hmac = ?", ("0" * 64,))
    assert store.verify_audit().valid is False
    with pytest.raises(AuditIntegrityError, match="authentication"):
        store.append_audit(
            principal,
            action="aggregate_query",
            outcome="allowed",
            request_id="request-0002",
            query_hash="b" * 64,
            reason_codes=["ALLOW"],
        )

    with sqlite3.connect(store.path) as connection:
        connection.execute("DELETE FROM audit_checkpoint")
    assert store.verify_audit().valid is False
    with pytest.raises(AuditIntegrityError, match="missing"):
        store.append_audit(
            principal,
            action="aggregate_query",
            outcome="allowed",
            request_id="request-0003",
            query_hash="c" * 64,
            reason_codes=["ALLOW"],
        )
    with pytest.raises(AuditIntegrityError, match="missing"):
        StateStore(store.path, b"audit" * 8)


def test_audit_verifier_rejects_non_list_reasons_and_head_mismatch(store: StateStore) -> None:
    principal = Principal(subject="unit.analyst", role=Role.ANALYST)
    store.append_audit(
        principal,
        action="aggregate_query",
        outcome="allowed",
        request_id="request-0001",
        query_hash="a" * 64,
        reason_codes=["ALLOW"],
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE audit_log SET reason_codes = '{}' WHERE id = 1")
    assert store.verify_audit().first_invalid_entry == 1

    replacement_head = "f" * 64
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE audit_log SET reason_codes = '[\"ALLOW\"]' WHERE id = 1")
        connection.execute(
            "UPDATE audit_checkpoint SET head_hash = ?, checkpoint_hmac = ?",
            (replacement_head, store._checkpoint_hmac(1, replacement_head)),
        )
    verification = store.verify_audit()
    assert verification.valid is False and verification.entries_checked == 1


def test_legacy_state_establishes_one_time_local_checkpoint(store: StateStore) -> None:
    principal = Principal(subject="unit.analyst", role=Role.ANALYST)
    store.append_audit(
        principal,
        action="aggregate_query",
        outcome="allowed",
        request_id="request-0001",
        query_hash="a" * 64,
        reason_codes=["ALLOW"],
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TABLE audit_checkpoint")
        connection.execute("PRAGMA user_version = 0")
    migrated = StateStore(store.path, b"audit" * 8)
    assert migrated.verify_audit().model_dump() == {
        "valid": True,
        "entries_checked": 1,
        "first_invalid_entry": None,
    }


def test_state_rejects_weak_audit_key(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="32"):
        StateStore(tmp_path / "state.db", b"weak")
