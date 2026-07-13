from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator

Scalar: TypeAlias = str | int | float | bool | None


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Role(StrEnum):
    ANALYST = "analyst"
    PRIVACY_OFFICER = "privacy_officer"
    AUDITOR = "auditor"


class Principal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.@-]+$")
    role: Role


class MetricPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    column: str
    functions: frozenset[Literal["avg", "count"]]
    lower: float | None = None
    upper: float | None = None

    @field_validator("upper")
    @classmethod
    def validate_upper(cls, value: float | None, info: Any) -> float | None:
        lower = info.data.get("lower")
        if value is not None and lower is not None and value <= lower:
            raise ValueError("upper must be greater than lower")
        return value


class DatasetPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    dataset: str = "workforce-v1"
    table: str = "employees"
    dataset_version: str = "2026-07-12"
    dimensions: frozenset[str]
    filter_columns: frozenset[str]
    forbidden_columns: frozenset[str]
    metrics: dict[str, MetricPolicy]
    min_group_size: int = Field(default=10, ge=3, le=1000)
    max_result_rows: int = Field(default=100, ge=1, le=1000)
    default_epsilon: float = Field(default=0.5, gt=0, le=2)
    max_epsilon_per_query: float = Field(default=1.0, gt=0, le=5)
    principal_budget: float = Field(default=5.0, gt=0, le=100)
    max_filters: int = Field(default=4, ge=0, le=10)


@dataclass(frozen=True, slots=True)
class FilterPredicate:
    column: str
    operator: Literal["eq", "neq", "in"]
    values: tuple[Scalar, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"column": self.column, "operator": self.operator, "values": self.values}


@dataclass(frozen=True, slots=True)
class Metric:
    function: Literal["avg", "count"]
    column: str | None
    alias: str

    def as_dict(self) -> dict[str, str | None]:
        return {"function": self.function, "column": self.column, "alias": self.alias}


@dataclass(frozen=True, slots=True)
class QueryPlan:
    dataset: str
    dimensions: tuple[str, ...]
    metrics: tuple[Metric, ...]
    filters: tuple[FilterPredicate, ...]

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "dataset": self.dataset,
            "dimensions": self.dimensions,
            "metrics": [metric.as_dict() for metric in self.metrics],
            "filters": [predicate.as_dict() for predicate in self.filters],
        }

    def canonical_json(self) -> str:
        return json.dumps(self.canonical_payload(), sort_keys=True, separators=(",", ":"))

    def fingerprint(self) -> str:
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()


class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sql: str = Field(min_length=1, max_length=8_000)
    epsilon: float | None = Field(default=None, gt=0, le=5)
    request_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )


class PrivacyMetadata(BaseModel):
    mechanism: str
    epsilon: float
    budget_spent: float
    budget_remaining: float
    sticky_noise: bool
    minimum_group_size: int
    suppressed_groups: int | None


class QueryResponse(BaseModel):
    request_id: str
    decision: Decision
    reason_codes: list[str]
    canonical_query: str | None = None
    columns: list[str] = Field(default_factory=list)
    rows: list[dict[str, Scalar]] = Field(default_factory=list)
    privacy: PrivacyMetadata | None = None
    audit_entry_id: int
    elapsed_ms: float


class ExplainResponse(BaseModel):
    decision: Decision
    reason_codes: list[str]
    canonical_plan: dict[str, Any] | None = None
    rewritten_sql: str | None = None
    parameters: list[Scalar] = Field(default_factory=list)


class AuditVerification(BaseModel):
    valid: bool
    entries_checked: int
    first_invalid_entry: int | None = None


class BudgetSnapshot(BaseModel):
    principal: str
    spent: float
    remaining: float
    limit: float


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    dataset: str
    dataset_version: str


class ErrorResponse(BaseModel):
    detail: str
    code: str
