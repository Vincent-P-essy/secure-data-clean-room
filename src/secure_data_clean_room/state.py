from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import AuditVerification, BudgetSnapshot, Principal, QueryPlan

_STATE_SCHEMA_VERSION = 2
_ZERO_HASH = "0" * 64


class BudgetExceeded(RuntimeError):
    pass


class DifferencingRisk(RuntimeError):
    pass


class AuditIntegrityError(RuntimeError):
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
            prior_schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS privacy_spend (
                    principal TEXT NOT NULL,
                    dataset_version TEXT NOT NULL,
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
                CREATE TABLE IF NOT EXISTS audit_checkpoint (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    entry_count INTEGER NOT NULL CHECK (entry_count >= 0),
                    head_hash TEXT NOT NULL CHECK (length(head_hash) = 64),
                    checkpoint_hmac TEXT NOT NULL CHECK (length(checkpoint_hmac) = 64)
                );
                """
            )
            spend_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(privacy_spend)").fetchall()
            }
            if "dataset_version" not in spend_columns:
                connection.execute(
                    "ALTER TABLE privacy_spend "
                    "ADD COLUMN dataset_version TEXT NOT NULL DEFAULT 'legacy-unversioned'"
                )

            checkpoint = connection.execute(
                "SELECT entry_count FROM audit_checkpoint WHERE singleton = 1"
            ).fetchone()
            if checkpoint is None:
                if prior_schema_version >= _STATE_SCHEMA_VERSION:
                    raise AuditIntegrityError("local audit checkpoint is missing")
                entries = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
                verification, head_hash = self._verify_entries(entries)
                if not verification.valid:
                    raise AuditIntegrityError(
                        "cannot establish migration checkpoint over an invalid audit chain"
                    )
                entry_count = len(entries)
                connection.execute(
                    "INSERT INTO audit_checkpoint VALUES (1, ?, ?, ?)",
                    (
                        entry_count,
                        head_hash,
                        self._checkpoint_hmac(entry_count, head_hash),
                    ),
                )
            connection.execute(f"PRAGMA user_version = {_STATE_SCHEMA_VERSION}")

    def reserve_budget(
        self,
        principal: str,
        dataset_version: str,
        fingerprint: str,
        epsilon: float,
        limit: float,
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
                    """
                    INSERT INTO privacy_spend
                        (principal, dataset_version, query_fingerprint, epsilon, charged_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (principal, dataset_version, fingerprint, epsilon, now),
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
        structure_payload = plan.variant_structure_payload()
        structure_hash = hashlib.sha256(
            json.dumps(structure_payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        filter_hash = hashlib.sha256(
            json.dumps(
                plan.semantic_filters_payload(),
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
            checkpoint = connection.execute(
                "SELECT * FROM audit_checkpoint WHERE singleton = 1"
            ).fetchone()
            if checkpoint is None:
                connection.rollback()
                raise AuditIntegrityError("local audit checkpoint is missing")
            try:
                entry_count = int(checkpoint["entry_count"])
                previous_hash = str(checkpoint["head_hash"])
                checkpoint_hmac = str(checkpoint["checkpoint_hmac"])
            except (KeyError, TypeError, ValueError) as error:
                connection.rollback()
                raise AuditIntegrityError("local audit checkpoint is malformed") from error
            expected_checkpoint = self._checkpoint_hmac(entry_count, previous_hash)
            if not hmac.compare_digest(expected_checkpoint, checkpoint_hmac):
                connection.rollback()
                raise AuditIntegrityError("local audit checkpoint authentication failed")
            tail = connection.execute(
                "SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            tail_count = 0 if tail is None else int(tail["id"])
            tail_hash = _ZERO_HASH if tail is None else str(tail["entry_hash"])
            if tail_count != entry_count or not hmac.compare_digest(tail_hash, previous_hash):
                connection.rollback()
                raise AuditIntegrityError("audit log does not match its local checkpoint")

            entry_id = entry_count + 1
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
            connection.execute(
                """
                UPDATE audit_checkpoint
                SET entry_count = ?, head_hash = ?, checkpoint_hmac = ?
                WHERE singleton = 1
                """,
                (
                    entry_id,
                    entry_hash,
                    self._checkpoint_hmac(entry_id, entry_hash),
                ),
            )
            connection.commit()
        return entry_id

    def verify_audit(self) -> AuditVerification:
        with self._connect() as connection:
            entries = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
            checkpoint = connection.execute(
                "SELECT * FROM audit_checkpoint WHERE singleton = 1"
            ).fetchone()
        if checkpoint is None:
            return AuditVerification(valid=False, entries_checked=0)
        try:
            expected_count = int(checkpoint["entry_count"])
            expected_head = str(checkpoint["head_hash"])
            checkpoint_hmac = str(checkpoint["checkpoint_hmac"])
        except (KeyError, TypeError, ValueError):
            return AuditVerification(valid=False, entries_checked=0)
        expected_checkpoint = self._checkpoint_hmac(expected_count, expected_head)
        if not hmac.compare_digest(expected_checkpoint, checkpoint_hmac):
            return AuditVerification(valid=False, entries_checked=0)

        verification, actual_head = self._verify_entries(entries)
        if not verification.valid:
            return verification
        if len(entries) != expected_count:
            return AuditVerification(
                valid=False,
                entries_checked=len(entries),
                first_invalid_entry=len(entries) + 1,
            )
        if not hmac.compare_digest(actual_head, expected_head):
            return AuditVerification(
                valid=False,
                entries_checked=len(entries),
                first_invalid_entry=expected_count if expected_count else None,
            )
        return AuditVerification(valid=True, entries_checked=len(entries))

    def _verify_entries(self, entries: list[sqlite3.Row]) -> tuple[AuditVerification, str]:
        previous_hash = _ZERO_HASH
        for index, entry in enumerate(entries, start=1):
            if int(entry["id"]) != index or entry["previous_hash"] != previous_hash:
                return (
                    AuditVerification(
                        valid=False,
                        entries_checked=index - 1,
                        first_invalid_entry=int(entry["id"]),
                    ),
                    previous_hash,
                )
            try:
                reason_codes = json.loads(entry["reason_codes"])
            except (json.JSONDecodeError, TypeError):
                return (
                    AuditVerification(
                        valid=False, entries_checked=index - 1, first_invalid_entry=index
                    ),
                    previous_hash,
                )
            if not isinstance(reason_codes, list) or not all(
                isinstance(reason, str) for reason in reason_codes
            ):
                return (
                    AuditVerification(
                        valid=False, entries_checked=index - 1, first_invalid_entry=index
                    ),
                    previous_hash,
                )
            try:
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
                        "reason_codes": reason_codes,
                        "previous_hash": entry["previous_hash"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            except (KeyError, TypeError, ValueError):
                return (
                    AuditVerification(
                        valid=False, entries_checked=index - 1, first_invalid_entry=index
                    ),
                    previous_hash,
                )
            expected = hmac.new(self.audit_key, canonical.encode(), "sha256").hexdigest()
            if not hmac.compare_digest(expected, str(entry["entry_hash"])):
                return (
                    AuditVerification(
                        valid=False, entries_checked=index - 1, first_invalid_entry=int(entry["id"])
                    ),
                    previous_hash,
                )
            previous_hash = str(entry["entry_hash"])
        return AuditVerification(valid=True, entries_checked=len(entries)), previous_hash

    def _checkpoint_hmac(self, entry_count: int, head_hash: str) -> str:
        canonical = json.dumps(
            {
                "schema": "local-audit-checkpoint-v1",
                "entry_count": entry_count,
                "head_hash": head_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hmac.new(self.audit_key, canonical.encode(), "sha256").hexdigest()
