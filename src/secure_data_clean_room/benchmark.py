from __future__ import annotations

import csv
import hashlib
import json
import platform
import tempfile
from pathlib import Path
from typing import Any

from .models import Decision, Principal, QueryRequest, Role
from .service import CleanRoomService
from .settings import Settings


def run_benchmark(
    settings: Settings,
    *,
    corpus_path: Path,
    output_directory: Path,
    iterations: int = 10,
) -> dict[str, Any]:
    if iterations < 1 or iterations > 1_000:
        raise ValueError("iterations must be between 1 and 1000")
    raw_corpus = corpus_path.read_bytes()
    corpus = json.loads(raw_corpus)
    if not isinstance(corpus, list) or not corpus:
        raise ValueError("benchmark corpus must be a non-empty JSON array")

    case_reports: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="clean-room-benchmark-") as temporary:
        root = Path(temporary)
        isolated = Settings(
            policy_path=settings.policy_path,
            dataset_path=root / "workforce.db",
            state_path=root / "state.db",
            noise_key=settings.noise_key,
            audit_key=settings.audit_key,
            pseudonym_key=settings.pseudonym_key,
            api_principals=settings.api_principals,
        )
        service = CleanRoomService(isolated)
        service.initialize_demo()
        for index, case in enumerate(corpus):
            expected = Decision(case["expected"])
            latencies: list[float] = []
            decisions: list[Decision] = []
            reason_codes: list[str] = []
            principal = Principal(subject=f"benchmark.{index:03d}", role=Role.ANALYST)
            for iteration in range(iterations):
                response = service.query(
                    QueryRequest(
                        sql=case["sql"],
                        epsilon=case.get("epsilon"),
                        request_id=f"bench-{index:03d}-{iteration:04d}",
                    ),
                    principal,
                )
                decisions.append(response.decision)
                reason_codes = response.reason_codes
                latencies.append(response.elapsed_ms)
            actual = decisions[-1]
            case_reports.append(
                {
                    "id": case["id"],
                    "expected": expected.value,
                    "actual": actual.value,
                    "passed": all(decision is expected for decision in decisions),
                    "reason_codes": reason_codes,
                    "latency_p50_ms": round(_percentile(latencies, 50), 3),
                    "latency_p95_ms": round(_percentile(latencies, 95), 3),
                }
            )
        audit = service.state.verify_audit()

    all_passed = sum(1 for case in case_reports if case["passed"])
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "corpus_sha256": hashlib.sha256(raw_corpus).hexdigest(),
        "cases": len(case_reports),
        "iterations_per_case": iterations,
        "expectation_accuracy": all_passed / len(case_reports),
        "allowed_cases": sum(1 for case in case_reports if case["expected"] == "ALLOW"),
        "denied_cases": sum(1 for case in case_reports if case["expected"] == "DENY"),
        "audit_chain_valid": audit.valid,
        "audit_entries": audit.entries_checked,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "results": case_reports,
    }
    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "benchmark.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_csv(output_directory / "benchmark.csv", case_reports)
    (output_directory / "BENCHMARK.md").write_text(_markdown(report), encoding="utf-8")
    return report


def _percentile(values: list[float], percentile: int) -> float:
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile / 100
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _write_csv(path: Path, cases: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=(
                "id",
                "expected",
                "actual",
                "passed",
                "latency_p50_ms",
                "latency_p95_ms",
                "reason_codes",
            ),
        )
        writer.writeheader()
        for case in cases:
            writer.writerow({**case, "reason_codes": ";".join(case["reason_codes"])})


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Secure Data Clean Room benchmark",
        "",
        f"- Policy expectation accuracy: **{report['expectation_accuracy']:.1%}**",
        f"- Cases: **{report['cases']}** ({report['allowed_cases']} allow / "
        f"{report['denied_cases']} deny)",
        f"- Iterations per case: **{report['iterations_per_case']}**",
        f"- Audit chain valid after run: **{str(report['audit_chain_valid']).lower()}**",
        "",
        "| Case | Expected | Actual | p50 | p95 | Reasons |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for case in report["results"]:
        lines.append(
            f"| {case['id']} | {case['expected']} | {case['actual']} | "
            f"{case['latency_p50_ms']:.3f} ms | {case['latency_p95_ms']:.3f} ms | "
            f"{', '.join(case['reason_codes'])} |"
        )
    lines.extend(
        [
            "",
            "Latencies cover local policy parsing, ledger operations, SQLite execution, privacy "
            "transformation, and audit append. They are not production throughput claims.",
            "",
        ]
    )
    return "\n".join(lines)
