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
from secure_data_clean_room.policy import load_policy


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

    reader = ReadOnlyDataset(path, load_policy(repository_root / "fixtures/policy.json"))
    rows = reader.execute(
        'SELECT "department", AVG("salary") AS "average", COUNT(*) AS "__group_size" '
        'FROM "employees" GROUP BY "department" HAVING COUNT(*) >= ? LIMIT ?',
        [10, 100],
    )
    assert len(rows) == 6
    assert all(int(row["__group_size"] or 0) == 30 for row in rows)


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
    reader = ReadOnlyDataset(path, load_policy(repository_root / "fixtures/policy.json"))
    with pytest.raises(DatasetExecutionError, match="read-only query failed"):
        reader.execute("SELECT subject_token FROM employees", [])
    with pytest.raises(DatasetExecutionError, match="read-only query failed"):
        reader.execute("PRAGMA schema_version", [])


def test_missing_dataset_and_unsupported_scalar(tmp_path: Path, repository_root: Path) -> None:
    reader = ReadOnlyDataset(
        tmp_path / "missing.db", load_policy(repository_root / "fixtures/policy.json")
    )
    with pytest.raises(DatasetExecutionError, match="does not exist"):
        reader.execute("SELECT 1", [])
    with pytest.raises(DatasetExecutionError, match="unsupported"):
        _sqlite_scalar(b"bytes")
