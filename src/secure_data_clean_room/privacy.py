from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass

from .models import DatasetPolicy, Metric, QueryPlan, Scalar


@dataclass(frozen=True, slots=True)
class PrivacyResult:
    rows: list[dict[str, Scalar]]
    mechanism: str


class PrivacyMechanism:
    """Educational bounded Laplace mechanism with deterministic per-query noise."""

    def __init__(self, policy: DatasetPolicy, noise_key: bytes) -> None:
        if len(noise_key) < 32:
            raise ValueError("noise key must contain at least 32 bytes")
        self.policy = policy
        self.noise_key = noise_key

    def protect(
        self,
        rows: list[dict[str, Scalar]],
        plan: QueryPlan,
        epsilon: float,
        release_fingerprint: str,
    ) -> PrivacyResult:
        epsilon_per_metric = epsilon / len(plan.metrics)
        protected: list[dict[str, Scalar]] = []
        for row in rows:
            group_size = int(row.get("__group_size") or 0)
            if group_size < self.policy.min_group_size:
                continue
            group_key = json.dumps(
                [(dimension, row.get(dimension)) for dimension in sorted(plan.dimensions)],
                separators=(",", ":"),
            )
            output: dict[str, Scalar] = {
                dimension: row.get(dimension) for dimension in plan.dimensions
            }
            for metric in plan.metrics:
                raw = row.get(metric.alias)
                if not isinstance(raw, (int, float)):
                    output[metric.alias] = None
                    continue
                scale = self._scale(metric, group_size, epsilon_per_metric)
                token = (
                    f"{self.policy.dataset_version}\0{release_fingerprint}\0"
                    f"{group_key}\0{metric.function}:{metric.column or '*'}"
                )
                value = float(raw) + self._laplace(token, scale)
                if metric.function == "avg" and metric.column is not None:
                    metric_policy = self.policy.metrics[metric.column]
                    if metric_policy.lower is not None:
                        value = max(metric_policy.lower, value)
                    if metric_policy.upper is not None:
                        value = min(metric_policy.upper, value)
                    output[metric.alias] = round(value, 2)
                else:
                    output[metric.alias] = max(0, round(value))
            protected.append(output)
        return PrivacyResult(
            rows=protected,
            mechanism="bounded-laplace-v1 (sticky HMAC-derived noise; educational)",
        )

    def _scale(self, metric: Metric, group_size: int, epsilon: float) -> float:
        if metric.function == "count":
            sensitivity = 1.0
        elif metric.column is not None:
            configured = self.policy.metrics[metric.column]
            if configured.lower is None or configured.upper is None:
                raise ValueError(f"metric {metric.column} lacks privacy bounds")
            sensitivity = (configured.upper - configured.lower) / group_size
        else:  # pragma: no cover - Metric is policy generated.
            raise AssertionError("unreachable metric")
        return sensitivity / epsilon

    def _laplace(self, token: str, scale: float) -> float:
        digest = hmac.new(self.noise_key, token.encode(), hashlib.sha256).digest()
        integer = int.from_bytes(digest[:8], "big")
        uniform = (integer + 0.5) / 2**64 - 0.5
        sign = 1.0 if uniform >= 0 else -1.0
        return -scale * sign * math.log1p(-2 * abs(uniform))
