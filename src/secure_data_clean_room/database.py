from __future__ import annotations

import hashlib
import hmac
import random
import sqlite3
import time
from pathlib import Path
from typing import Final

from .models import DatasetPolicy, Scalar

_DEPARTMENTS: Final = ("Engineering", "Finance", "Operations", "Risk", "Sales", "Support")
_REGIONS: Final = ("France", "Germany", "Spain")
_JOBS: Final = ("analyst", "engineer", "manager", "specialist")
_AGE_BANDS: Final = ("20-29", "30-39", "40-49", "50-59")


class DatasetExecutionError(RuntimeError):
    pass


def initialize_demo_dataset(path: Path, pseudonym_key: bytes, *, rows: int = 180) -> None:
    """Create deterministic synthetic records; no real-world identity is persisted."""
    if len(pseudonym_key) < 32:
        raise ValueError("pseudonym key must contain at least 32 bytes")
    if rows < 120:
        raise ValueError("demo dataset requires at least 120 records")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    randomizer = random.Random(20260712)  # noqa: S311 - synthetic data, not a secret.
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = FULL;
            CREATE TABLE employees (
                subject_token TEXT PRIMARY KEY,
                department TEXT NOT NULL,
                region TEXT NOT NULL,
                job_family TEXT NOT NULL,
                age_band TEXT NOT NULL,
                active INTEGER NOT NULL CHECK (active IN (0, 1)),
                salary REAL NOT NULL CHECK (salary BETWEEN 25000 AND 250000),
                performance_score REAL NOT NULL CHECK (performance_score BETWEEN 1 AND 5)
            ) STRICT;
            CREATE TABLE dataset_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) STRICT;
            CREATE INDEX employees_dimensions
                ON employees(department, region, job_family, age_band, active);
            """
        )
        department_offsets = {
            "Engineering": 35_000,
            "Finance": 25_000,
            "Operations": 8_000,
            "Risk": 30_000,
            "Sales": 15_000,
            "Support": 0,
        }
        records: list[tuple[str, str, str, str, str, int, float, float]] = []
        for index in range(rows):
            department = _DEPARTMENTS[index % len(_DEPARTMENTS)]
            region = _REGIONS[(index // len(_DEPARTMENTS)) % len(_REGIONS)]
            job = _JOBS[(index // 3) % len(_JOBS)]
            age_band = _AGE_BANDS[(index // 7) % len(_AGE_BANDS)]
            active = 0 if index % 17 == 0 else 1
            base = 38_000 + department_offsets[department] + _JOBS.index(job) * 11_000
            salary = float(max(25_000, min(250_000, base + randomizer.randint(-7_500, 12_500))))
            performance = round(1.0 + randomizer.random() * 4.0, 2)
            synthetic_identifier = f"synthetic-subject-{index:04d}".encode()
            token = hmac.new(pseudonym_key, synthetic_identifier, hashlib.sha256).hexdigest()[:32]
            records.append((token, department, region, job, age_band, active, salary, performance))
        connection.executemany("INSERT INTO employees VALUES (?, ?, ?, ?, ?, ?, ?, ?)", records)
        connection.executemany(
            "INSERT INTO dataset_metadata VALUES (?, ?)",
            (
                ("dataset_version", "2026-07-12"),
                ("record_count", str(rows)),
                ("source", "deterministic synthetic fixture"),
                ("contains_real_personal_data", "false"),
            ),
        )
        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()


class ReadOnlyDataset:
    def __init__(
        self,
        path: Path,
        policy: DatasetPolicy,
        *,
        statement_timeout_ms: int = 250,
        maximum_vm_steps: int = 100_000,
    ) -> None:
        self.path = path.resolve()
        self.policy = policy
        self.statement_timeout_ms = statement_timeout_ms
        self.maximum_vm_steps = maximum_vm_steps

    def execute(self, sql: str, parameters: list[Scalar]) -> list[dict[str, Scalar]]:
        if not self.path.is_file():
            raise DatasetExecutionError(f"dataset does not exist: {self.path}")
        connection = sqlite3.connect(
            f"file:{self.path.as_posix()}?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
            timeout=1,
        )
        connection.row_factory = sqlite3.Row
        started = time.monotonic()
        steps = 0

        allowed_columns = set(self.policy.dimensions)
        allowed_columns.update(metric.column for metric in self.policy.metrics.values())
        allowed_columns.add("")

        def authorize(
            action: int,
            arg1: str | None,
            arg2: str | None,
            _database: str | None,
            _trigger: str | None,
        ) -> int:
            if action == sqlite3.SQLITE_SELECT:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_READ:
                if arg1 == self.policy.table and (arg2 or "") in allowed_columns:
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in {"avg", "count"}:
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        def progress() -> int:
            nonlocal steps
            steps += 1_000
            elapsed_ms = (time.monotonic() - started) * 1_000
            return int(steps > self.maximum_vm_steps or elapsed_ms > self.statement_timeout_ms)

        try:
            connection.set_authorizer(authorize)
            connection.set_progress_handler(progress, 1_000)
            cursor = connection.execute(sql, parameters)
            records = cursor.fetchmany(self.policy.max_result_rows + 1)
            if len(records) > self.policy.max_result_rows:
                raise DatasetExecutionError("result row limit exceeded")
            return [
                {str(key): _sqlite_scalar(value) for key, value in dict(record).items()}
                for record in records
            ]
        except sqlite3.Error as error:
            raise DatasetExecutionError(f"read-only query failed: {error}") from error
        finally:
            connection.close()


def _sqlite_scalar(value: object) -> Scalar:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise DatasetExecutionError(f"unsupported SQLite result type {type(value).__name__}")
