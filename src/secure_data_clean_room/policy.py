from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal, cast

import sqlglot
from sqlglot import exp

from .models import (
    DatasetPolicy,
    FilterPredicate,
    Metric,
    Principal,
    QueryPlan,
    Role,
    Scalar,
)

_ALIAS = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class PolicyViolation(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def load_policy(path: Path) -> DatasetPolicy:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load dataset policy {path}: {error}") from error
    return DatasetPolicy.model_validate(payload)


class PolicyEngine:
    """Reduce a narrowly supported SQL SELECT AST to an allowlisted query plan."""

    def __init__(self, policy: DatasetPolicy) -> None:
        self.policy = policy

    def plan(self, sql: str, principal: Principal) -> QueryPlan:
        if principal.role is not Role.ANALYST:
            raise PolicyViolation(
                "ROLE_CANNOT_QUERY_DATA",
                f"role {principal.role.value} may inspect controls but cannot query the dataset",
            )
        try:
            statements = sqlglot.parse(sql, read="sqlite")
        except sqlglot.errors.ParseError as error:
            raise PolicyViolation(
                "SQL_PARSE_ERROR", "query is not valid SQLite SELECT syntax"
            ) from error
        if len(statements) != 1 or not isinstance(statements[0], exp.Select):
            raise PolicyViolation("SELECT_ONLY", "exactly one SELECT statement is required")
        statement = statements[0]
        self._reject_unsupported_shape(statement)
        self._validate_table(statement)

        dimensions: list[str] = []
        metrics: list[Metric] = []
        aliases: set[str] = set()
        for projection in statement.expressions:
            dimension, metric = self._projection(projection)
            if dimension is None and metric is None:  # pragma: no cover - guarded by _projection.
                raise AssertionError("projection produced no output")
            alias = dimension if dimension is not None else cast(Metric, metric).alias
            if alias in aliases:
                raise PolicyViolation("DUPLICATE_OUTPUT", f"duplicate output name {alias}")
            aliases.add(alias)
            if dimension is not None:
                dimensions.append(dimension)
            if metric is not None:
                metrics.append(metric)

        if not metrics:
            raise PolicyViolation(
                "AGGREGATE_REQUIRED", "analyst queries must contain an approved aggregate"
            )
        if len(set(dimensions)) != len(dimensions):
            raise PolicyViolation("DUPLICATE_DIMENSION", "a dimension may be selected only once")

        group = statement.args.get("group")
        grouped = [] if group is None else [self._plain_column(item) for item in group.expressions]
        if set(grouped) != set(dimensions) or len(grouped) != len(dimensions):
            raise PolicyViolation(
                "INVALID_GROUPING", "every selected dimension must appear exactly once in GROUP BY"
            )

        filters: list[FilterPredicate] = []
        where = statement.args.get("where")
        if where is not None:
            filters = self._filters(where.this)
        if len(filters) > self.policy.max_filters:
            raise PolicyViolation(
                "TOO_MANY_FILTERS", f"at most {self.policy.max_filters} predicates are permitted"
            )

        return QueryPlan(
            dataset=self.policy.dataset,
            dimensions=tuple(dimensions),
            metrics=tuple(metrics),
            filters=tuple(filters),
        )

    def compile(self, plan: QueryPlan) -> tuple[str, list[Scalar]]:
        select_parts = [self._quote(column) for column in plan.dimensions]
        for metric in plan.metrics:
            if metric.function == "count":
                expression = "COUNT(*)"
            elif metric.function == "avg" and metric.column is not None:
                expression = f"AVG({self._quote(metric.column)})"
            else:  # pragma: no cover - QueryPlan is produced only by this engine.
                raise AssertionError(f"unsupported metric {metric.function}")
            select_parts.append(f"{expression} AS {self._quote(metric.alias)}")
        select_parts.append('COUNT(*) AS "__group_size"')

        parameters: list[Scalar] = []
        where_parts: list[str] = []
        for predicate in plan.filters:
            column = self._quote(predicate.column)
            if predicate.operator == "eq":
                where_parts.append(f"{column} = ?")
                parameters.append(predicate.values[0])
            elif predicate.operator == "neq":
                where_parts.append(f"{column} != ?")
                parameters.append(predicate.values[0])
            elif predicate.operator == "in":
                placeholders = ", ".join("?" for _ in predicate.values)
                where_parts.append(f"{column} IN ({placeholders})")
                parameters.extend(predicate.values)

        fragments = [f"SELECT {', '.join(select_parts)}", f"FROM {self._quote(self.policy.table)}"]
        if where_parts:
            fragments.append("WHERE " + " AND ".join(where_parts))
        if plan.dimensions:
            fragments.append("GROUP BY " + ", ".join(self._quote(item) for item in plan.dimensions))
        fragments.append("HAVING COUNT(*) >= ?")
        parameters.append(self.policy.min_group_size)
        if plan.dimensions:
            fragments.append("ORDER BY " + ", ".join(self._quote(item) for item in plan.dimensions))
        fragments.append("LIMIT ?")
        parameters.append(self.policy.max_result_rows)
        return "\n".join(fragments), parameters

    def _reject_unsupported_shape(self, statement: exp.Select) -> None:
        forbidden: tuple[type[exp.Expression], ...] = (
            exp.Join,
            exp.Subquery,
            exp.Union,
            exp.Intersect,
            exp.Except,
            exp.With,
            exp.Window,
            exp.Having,
            exp.Limit,
            exp.Offset,
            exp.Distinct,
        )
        for node_type in forbidden:
            if statement.find(node_type) is not None:
                raise PolicyViolation(
                    "UNSUPPORTED_QUERY_SHAPE",
                    f"{node_type.__name__} is outside the clean-room query subset",
                )
        if any(isinstance(node, exp.Star) for node in statement.expressions):
            raise PolicyViolation("WILDCARD_FORBIDDEN", "raw wildcard projection is forbidden")

    def _validate_table(self, statement: exp.Select) -> None:
        tables = list(statement.find_all(exp.Table))
        if len(tables) != 1 or tables[0].name.lower() != self.policy.table.lower():
            raise PolicyViolation(
                "DATASET_NOT_ALLOWED", f"query must use only the {self.policy.table} dataset"
            )
        if tables[0].db or tables[0].catalog:
            raise PolicyViolation(
                "QUALIFIED_TABLE_FORBIDDEN", "database qualification is forbidden"
            )

    def _projection(self, projection: exp.Expression) -> tuple[str | None, Metric | None]:
        alias: str | None = None
        expression = projection
        if isinstance(projection, exp.Alias):
            alias = projection.alias
            expression = projection.this
            if not _ALIAS.fullmatch(alias) or alias.startswith("__"):
                raise PolicyViolation("INVALID_ALIAS", "output alias is invalid or reserved")

        if isinstance(expression, exp.Column):
            if alias is not None:
                raise PolicyViolation(
                    "DIMENSION_ALIAS_FORBIDDEN", "dimension aliases are not supported"
                )
            column = self._plain_column(expression)
            if column in self.policy.forbidden_columns:
                raise PolicyViolation(
                    "DIRECT_IDENTIFIER", f"direct identifier {column} is forbidden"
                )
            if column not in self.policy.dimensions:
                raise PolicyViolation(
                    "RAW_SENSITIVE_COLUMN", f"raw projection of {column} is forbidden"
                )
            return column, None

        if isinstance(expression, exp.Avg):
            column = self._plain_column(expression.this)
            metric_policy = self.policy.metrics.get(column)
            if metric_policy is None or "avg" not in metric_policy.functions:
                raise PolicyViolation("METRIC_NOT_ALLOWED", f"AVG({column}) is not allowed")
            return None, Metric("avg", column, alias or f"avg_{column}")

        if isinstance(expression, exp.Count):
            if not isinstance(expression.this, exp.Star):
                raise PolicyViolation("COUNT_ONLY_ROWS", "only COUNT(*) is allowed")
            metric_policy = self.policy.metrics.get("rows")
            if metric_policy is None or "count" not in metric_policy.functions:
                raise PolicyViolation("METRIC_NOT_ALLOWED", "COUNT(*) is not allowed")
            return None, Metric("count", None, alias or "row_count")

        raise PolicyViolation(
            "EXPRESSION_NOT_ALLOWED",
            "only dimensions, AVG(approved_metric), and COUNT(*) are allowed",
        )

    def _plain_column(self, expression: exp.Expression) -> str:
        if not isinstance(expression, exp.Column):
            raise PolicyViolation("COLUMN_REQUIRED", "an allowlisted column is required")
        if expression.table and expression.table.lower() != self.policy.table.lower():
            raise PolicyViolation("COLUMN_QUALIFIER", "column qualifier is not allowed")
        return expression.name.lower()

    def _filters(self, expression: exp.Expression) -> list[FilterPredicate]:
        if isinstance(expression, exp.Paren):
            return self._filters(expression.this)
        if isinstance(expression, exp.And):
            return self._filters(cast(exp.Expression, expression.left)) + self._filters(
                cast(exp.Expression, expression.right)
            )
        if isinstance(expression, (exp.EQ, exp.NEQ)):
            column = self._filter_column(cast(exp.Expression, expression.left))
            value = self._literal(cast(exp.Expression, expression.right))
            operator: Literal["eq", "neq"] = "eq" if isinstance(expression, exp.EQ) else "neq"
            return [FilterPredicate(column, operator, (value,))]
        if isinstance(expression, exp.In):
            column = self._filter_column(expression.this)
            if expression.args.get("query") is not None:
                raise PolicyViolation("SUBQUERY_FORBIDDEN", "subqueries are forbidden")
            values = tuple(self._literal(item) for item in expression.expressions)
            if not values or len(values) > 20:
                raise PolicyViolation("INVALID_IN_LIST", "IN requires between one and 20 literals")
            return [FilterPredicate(column, "in", values)]
        raise PolicyViolation(
            "FILTER_NOT_ALLOWED", "filters support only AND-combined =, !=, and IN predicates"
        )

    def _filter_column(self, expression: exp.Expression) -> str:
        column = self._plain_column(expression)
        if column in self.policy.forbidden_columns:
            raise PolicyViolation("DIRECT_IDENTIFIER", f"filtering on {column} is forbidden")
        if column not in self.policy.filter_columns:
            raise PolicyViolation(
                "FILTER_COLUMN_NOT_ALLOWED", f"filtering on {column} is forbidden"
            )
        return column

    @staticmethod
    def _literal(expression: exp.Expression) -> Scalar:
        if isinstance(expression, exp.Boolean):
            return expression.this is True
        if not isinstance(expression, exp.Literal):
            raise PolicyViolation("LITERAL_REQUIRED", "filter values must be literals")
        if expression.is_string:
            return str(expression.this)
        try:
            number = float(expression.this)
        except ValueError as error:
            raise PolicyViolation("INVALID_LITERAL", "numeric literal is invalid") from error
        return int(number) if number.is_integer() else number

    @staticmethod
    def _quote(identifier: str) -> str:
        if not _ALIAS.fullmatch(identifier):  # defensive assertion for policy-controlled names.
            raise ValueError(f"unsafe identifier {identifier!r}")
        return f'"{identifier}"'
