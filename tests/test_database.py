from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from secure_data_clean_room.database import (
    DatasetExecutionError,
    ReadOnlyDataset,
    _sqlite_scalar,
    initialize_demo_dataset,
)
from secure_data_clean_room.models import Metric, Principal, QueryPlan, Role
from secure_data_clean_room.policy import PolicyEngine, load_policy


def test_demo_dataset_contains_only_pseudonyms(tmp_path: Path, repository_root: Path) -> None:
    path = tmp_path / "dataset.db"
    initialize_demo_dataset(path, b"p" * 32, rows=180)
    connection = sqlite3.connect(path)
    columns = [row[1] for row in connection.execute("PRAGMA table_info(employees)")]
    count = connection.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    tokens = [row[0] for row in connection.execute("SELECT subject_token FROM employees")]
    metadata = dict(connection.execute("SELECT key, value FROM dataset_metadata"))
    connection.close()
    assert count == 180
    assert "name" not in columns and "email" not in columns
    assert len(set(tokens)) == 180 and all(len(token) == 32 for token in tokens)
    assert metadata["contains_real_personal_data"] == "false"

    policy = load_policy(repository_root / "fixtures/policy.json")
    reader = ReadOnlyDataset(path, policy)
    plan = PolicyEngine(policy).plan(
        "SELECT department, AVG(salary) AS average FROM employees GROUP BY department",
        Principal(subject="database.test", role=Role.ANALYST),
    )
    execution = reader.execute(plan)
    rows = execution.rows
    assert len(rows) == 6
    assert all(int(row["__group_size"] or 0) == 30 for row in rows)
    assert "HAVING COUNT(*) >= ?" in execution.sql


def test_dataset_rejects_weak_key_and_small_fixture(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="32"):
        initialize_demo_dataset(tmp_path / "weak.db", b"weak")
    with pytest.raises(ValueError, match="120"):
        initialize_demo_dataset(tmp_path / "small.db", b"x" * 32, rows=20)


def test_read_only_executor_denies_untrusted_statement(
    tmp_path: Path, repository_root: Path
) -> None:
    path = tmp_path / "dataset.db"
    initialize_demo_dataset(path, b"x" * 32)
    policy = load_policy(repository_root / "fixtures/policy.json")
    reader = ReadOnlyDataset(path, policy)
    with pytest.raises(DatasetExecutionError, match="structured aggregate"):
        reader.execute("SELECT subject_token FROM employees")  # type: ignore[arg-type]
    unsafe_plan = QueryPlan(
        dataset=policy.dataset,
        dataset_version=policy.dataset_version,
        dimensions=("salary",),
        metrics=(Metric("count", None, "rows"),),
        filters=(),
    )
    with pytest.raises(DatasetExecutionError, match="rejected"):
        reader.execute(unsafe_plan)


def test_missing_dataset_and_unsupported_scalar(tmp_path: Path, repository_root: Path) -> None:
    policy = load_policy(repository_root / "fixtures/policy.json")
    reader = ReadOnlyDataset(tmp_path / "missing.db", policy)
    plan = PolicyEngine(policy).plan(
        "SELECT COUNT(*) FROM employees",
        Principal(subject="database.test", role=Role.ANALYST),
    )
    with pytest.raises(DatasetExecutionError, match="does not exist"):
        reader.execute(plan)
    with pytest.raises(DatasetExecutionError, match="unsupported"):
        _sqlite_scalar(b"bytes")
