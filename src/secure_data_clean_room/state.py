from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import AuditVerification, BudgetSnapshot, Principal, QueryPlan


class BudgetExceeded(RuntimeError):
    pass


class DifferencingRisk(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Reservation:
    snapshot: BudgetSnapshot
    newly_charged: bool


class StateStore:
    """Durable privacy ledger and HMAC-linked audit log."""

    def __init__(self, path: Path, audit_key: bytes) -> None:
        if len(audit_key) < 32:
            raise ValueError("audit key must contain at least 32 bytes")
        self.path = path
        self.audit_key = audit_key
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS privacy_spend (
                    principal TEXT NOT NULL,
                    query_fingerprint TEXT NOT NULL,
                    epsilon REAL NOT NULL CHECK (epsilon > 0),
                    charged_at TEXT NOT NULL,
                    PRIMARY KEY (principal, query_fingerprint)
                );
                CREATE TABLE IF NOT EXISTS query_history (
                    principal TEXT NOT NULL,
                    structure_hash TEXT NOT NULL,
                    filter_hash TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY (principal, structure_hash, filter_hash)
                );
                CREATE INDEX IF NOT EXISTS query_history_time
                    ON query_history(principal, observed_at);
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    query_hash TEXT NOT NULL,
                    reason_codes TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE
                );
                """
            )

    def reserve_budget(
        self, principal: str, fingerprint: str, epsilon: float, limit: float
    ) -> Reservation:
        now = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT epsilon FROM privacy_spend WHERE principal = ? AND query_fingerprint = ?",
                (principal, fingerprint),
            ).fetchone()
            spent = float(
                connection.execute(
                    "SELECT COALESCE(SUM(epsilon), 0) FROM privacy_spend WHERE principal = ?",
                    (principal,),
                ).fetchone()[0]
            )
            newly_charged = existing is None
            if newly_charged:
                if spent + epsilon > limit + 1e-12:
                    connection.rollback()
                    raise BudgetExceeded(
                        f"privacy budget exhausted: {spent:.3f} spent of {limit:.3f}"
                    )
                connection.execute(
                    "INSERT INTO privacy_spend VALUES (?, ?, ?, ?)",
                    (principal, fingerprint, epsilon, now),
                )
                spent += epsilon
            connection.commit()
        return Reservation(
            snapshot=BudgetSnapshot(
                principal=principal,
                spent=round(spent, 6),
                remaining=round(max(0.0, limit - spent), 6),
                limit=limit,
            ),
            newly_charged=newly_charged,
        )

    def budget(self, principal: str, limit: float) -> BudgetSnapshot:
        with self._connect() as connection:
            spent = float(
                connection.execute(
                    "SELECT COALESCE(SUM(epsilon), 0) FROM privacy_spend WHERE principal = ?",
                    (principal,),
                ).fetchone()[0]
            )
        return BudgetSnapshot(
            principal=principal,
            spent=round(spent, 6),
            remaining=round(max(0.0, limit - spent), 6),
            limit=limit,
        )

    def guard_query_variants(
        self,
        principal: str,
        plan: QueryPlan,
        *,
        maximum_variants: int = 4,
        window: timedelta = timedelta(hours=24),
    ) -> None:
        structure_payload = {
            "dataset": plan.dataset,
            "dimensions": plan.dimensions,
            "metrics": [metric.as_dict() for metric in plan.metrics],
            "filter_shape": [
                {"column": item.column, "operator": item.operator, "arity": len(item.values)}
                for item in plan.filters
            ],
        }
        structure_hash = hashlib.sha256(
            json.dumps(structure_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        filter_hash = hashlib.sha256(
            json.dumps(
                [item.as_dict() for item in plan.filters],
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        now = datetime.now(UTC)
        cutoff = (now - window).isoformat()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM query_history WHERE observed_at < ?", (cutoff,))
            existing = connection.execute(
                """
                SELECT 1 FROM query_history
                WHERE principal = ? AND structure_hash = ? AND filter_hash = ?
                """,
                (principal, structure_hash, filter_hash),
            ).fetchone()
            variants = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM query_history
                    WHERE principal = ? AND structure_hash = ?
                    """,
                    (principal, structure_hash),
                ).fetchone()[0]
            )
            if existing is None and variants >= maximum_variants:
                connection.rollback()
                raise DifferencingRisk(
                    "too many distinct filter variants for the same aggregate shape in 24 hours"
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO query_history
                    (principal, structure_hash, filter_hash, observed_at)
                VALUES (?, ?, ?, ?)
                """,
                (principal, structure_hash, filter_hash, now.isoformat()),
            )
            connection.commit()

    def append_audit(
        self,
        principal: Principal,
        *,
        action: str,
        outcome: str,
        request_id: str,
        query_hash: str,
        reason_codes: list[str],
    ) -> int:
        timestamp = datetime.now(UTC).isoformat()
        reasons = json.dumps(reason_codes, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            entry_id = 1 if previous is None else int(previous["id"]) + 1
            previous_hash = "0" * 64 if previous is None else str(previous["entry_hash"])
            canonical = json.dumps(
                {
                    "id": entry_id,
                    "timestamp": timestamp,
                    "principal": principal.subject,
                    "role": principal.role.value,
                    "action": action,
                    "outcome": outcome,
                    "request_id": request_id,
                    "query_hash": query_hash,
                    "reason_codes": json.loads(reasons),
                    "previous_hash": previous_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            entry_hash = hmac.new(self.audit_key, canonical.encode(), "sha256").hexdigest()
            connection.execute(
                """
                INSERT INTO audit_log
                    (id, timestamp, principal, role, action, outcome, request_id,
                     query_hash, reason_codes, previous_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry_id,
                    timestamp,
                    principal.subject,
                    principal.role.value,
                    action,
                    outcome,
                    request_id,
                    query_hash,
                    reasons,
                    previous_hash,
                    entry_hash,
                ),
            )
            connection.commit()
        return entry_id

    def verify_audit(self) -> AuditVerification:
        with self._connect() as connection:
            entries = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        previous_hash = "0" * 64
        for index, entry in enumerate(entries, start=1):
            if int(entry["id"]) != index or entry["previous_hash"] != previous_hash:
                return AuditVerification(
                    valid=False, entries_checked=index - 1, first_invalid_entry=int(entry["id"])
                )
            canonical = json.dumps(
                {
                    "id": int(entry["id"]),
                    "timestamp": entry["timestamp"],
                    "principal": entry["principal"],
                    "role": entry["role"],
                    "action": entry["action"],
                    "outcome": entry["outcome"],
                    "request_id": entry["request_id"],
                    "query_hash": entry["query_hash"],
                    "reason_codes": json.loads(entry["reason_codes"]),
                    "previous_hash": entry["previous_hash"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            expected = hmac.new(self.audit_key, canonical.encode(), "sha256").hexdigest()
            if not hmac.compare_digest(expected, str(entry["entry_hash"])):
                return AuditVerification(
                    valid=False, entries_checked=index - 1, first_invalid_entry=int(entry["id"])
                )
            previous_hash = str(entry["entry_hash"])
        return AuditVerification(valid=True, entries_checked=len(entries))
