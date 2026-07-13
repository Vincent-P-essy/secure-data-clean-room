from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .models import Decision, Principal, QueryRequest, QueryResponse, Role
from .service import CleanRoomService
from .settings import Settings
from .state import StateStore


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
    corpus = _validate_corpus(json.loads(raw_corpus))
    repository_root = _find_repository_root(corpus_path)
    inputs = _input_hashes(repository_root, corpus_path, settings.policy_path)

    case_reports: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
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
                observations.append(
                    {
                        "case_id": case["id"],
                        "iteration": iteration,
                        "expected": expected.value,
                        "response": response.model_dump(mode="json"),
                    }
                )
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

        controls = _run_control_checks(service, root, settings.audit_key)
        audit = service.state.verify_audit()

    all_passed = sum(1 for case in case_reports if case["passed"])
    controls_passed = sum(1 for control in controls if control["passed"])
    report: dict[str, Any] = {
        "schema_version": "2.0",
        "corpus_sha256": hashlib.sha256(raw_corpus).hexdigest(),
        "input_sha256": inputs,
        "source": _source_metadata(repository_root),
        "cases": len(case_reports),
        "iterations_per_case": iterations,
        "expectation_accuracy": all_passed / len(case_reports),
        "allowed_cases": sum(1 for case in case_reports if case["expected"] == "ALLOW"),
        "denied_cases": sum(1 for case in case_reports if case["expected"] == "DENY"),
        "control_checks": len(controls),
        "control_accuracy": controls_passed / len(controls),
        "audit_chain_valid": audit.valid,
        "audit_entries": audit.entries_checked,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "results": case_reports,
        "controls": controls,
    }
    _write_artifacts(output_directory, report, observations, inputs)
    return report


def _validate_corpus(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not payload:
        raise ValueError("benchmark corpus must be a non-empty JSON array")
    cases: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for item in payload:
        if not isinstance(item, dict) or set(item) - {"id", "expected", "sql", "epsilon"}:
            raise ValueError("each benchmark case must be a strict JSON object")
        identifier = item.get("id")
        sql = item.get("sql")
        expected = item.get("expected")
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise ValueError("benchmark case identifiers must be non-empty and unique")
        if not isinstance(sql, str) or not sql:
            raise ValueError("benchmark case SQL must be non-empty")
        if not isinstance(expected, str):
            raise ValueError("benchmark case expectation must be ALLOW or DENY")
        try:
            Decision(expected)
            QueryRequest(sql=sql, epsilon=item.get("epsilon"))
        except (ValueError, TypeError) as error:
            raise ValueError(f"invalid benchmark case {identifier}") from error
        identifiers.add(identifier)
        cases.append(item)
    return cases


def _run_control_checks(
    service: CleanRoomService, temporary_root: Path, audit_key: bytes
) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []

    sticky_principal = Principal(subject="control.sticky", role=Role.ANALYST)
    first = service.query(
        QueryRequest(
            sql="SELECT department, AVG(salary) AS first FROM employees GROUP BY department",
            request_id="control-sticky-0001",
        ),
        sticky_principal,
    )
    renamed = service.query(
        QueryRequest(
            sql="SELECT AVG(salary) AS renamed, department FROM employees GROUP BY department",
            request_id="control-sticky-0002",
        ),
        sticky_principal,
    )
    sticky_values = _metric_by_dimension(first, "department", "first")
    renamed_values = _metric_by_dimension(renamed, "department", "renamed")
    sticky_passed = (
        first.decision is Decision.ALLOW
        and renamed.decision is Decision.ALLOW
        and sticky_values == renamed_values
        and renamed.privacy is not None
        and renamed.privacy.budget_spent == 0.5
        and "STICKY_RELEASE_REUSED" in renamed.reason_codes
    )
    controls.append(
        _control(
            "sticky-equivalent-release",
            sticky_passed,
            {
                "budget_spent": renamed.privacy.budget_spent if renamed.privacy else None,
                "same_protected_values": sticky_values == renamed_values,
            },
        )
    )

    budget_principal = Principal(subject="control.budget", role=Role.ANALYST)
    budget_queries = (
        "SELECT COUNT(*) AS total FROM employees",
        "SELECT department, COUNT(*) AS total FROM employees GROUP BY department",
        "SELECT region, COUNT(*) AS total FROM employees GROUP BY region",
        "SELECT job_family, COUNT(*) AS total FROM employees GROUP BY job_family",
        "SELECT age_band, COUNT(*) AS total FROM employees GROUP BY age_band",
        "SELECT active, COUNT(*) AS total FROM employees GROUP BY active",
    )
    budget_responses = [
        service.query(
            QueryRequest(sql=sql, epsilon=1, request_id=f"control-budget-{index:04d}"),
            budget_principal,
        )
        for index, sql in enumerate(budget_queries)
    ]
    budget_passed = all(
        response.decision is Decision.ALLOW for response in budget_responses[:5]
    ) and budget_responses[-1].reason_codes == ["PRIVACY_BUDGET_EXHAUSTED"]
    controls.append(
        _control(
            "privacy-budget-exhaustion",
            budget_passed,
            {
                "decisions": [response.decision.value for response in budget_responses],
                "last_reason_codes": budget_responses[-1].reason_codes,
            },
        )
    )

    roles = (Role.AUDITOR, Role.PRIVACY_OFFICER)
    role_responses = [
        service.query(
            QueryRequest(
                sql="SELECT COUNT(*) FROM employees",
                request_id=f"control-role-{index:04d}",
            ),
            Principal(subject=f"control.{role.value}", role=role),
        )
        for index, role in enumerate(roles)
    ]
    roles_passed = all(
        response.reason_codes == ["ROLE_CANNOT_QUERY_DATA"] for response in role_responses
    )
    controls.append(
        _control(
            "control-plane-roles-denied-data",
            roles_passed,
            {"reason_codes": [response.reason_codes for response in role_responses]},
        )
    )

    slicing_principal = Principal(subject="control.slicing", role=Role.ANALYST)
    slice_queries = (
        "SELECT department, AVG(salary) AS slice_0 FROM employees "
        "WHERE region = 'France' GROUP BY department",
        "SELECT department, AVG(salary) AS slice_1 FROM employees "
        "WHERE region = 'Germany' GROUP BY department",
        "SELECT department, AVG(salary) AS slice_2 FROM employees "
        "WHERE region = 'Spain' GROUP BY department",
        "SELECT department, AVG(salary) AS slice_3 FROM employees "
        "WHERE region = 'Italy' GROUP BY department",
        "SELECT department, AVG(salary) AS slice_4 FROM employees "
        "WHERE region = 'Belgium' GROUP BY department",
    )
    slicing_responses = [
        service.query(
            QueryRequest(
                sql=sql,
                request_id=f"control-slice-{index:04d}",
            ),
            slicing_principal,
        )
        for index, sql in enumerate(slice_queries)
    ]
    differencing_passed = all(
        response.decision is Decision.ALLOW for response in slicing_responses[:4]
    ) and slicing_responses[-1].reason_codes == ["DIFFERENCING_RISK"]
    controls.append(
        _control(
            "canonical-differencing-guard",
            differencing_passed,
            {
                "decisions": [response.decision.value for response in slicing_responses],
                "last_reason_codes": slicing_responses[-1].reason_codes,
            },
        )
    )

    truncation_store = StateStore(temporary_root / "truncation-state.db", audit_key)
    audit_principal = Principal(subject="control.audit", role=Role.AUDITOR)
    for index in (1, 2):
        truncation_store.append_audit(
            audit_principal,
            action="control_check",
            outcome="allowed",
            request_id=f"control-audit-{index:04d}",
            query_hash=str(index) * 64,
            reason_codes=["CONTROL"],
        )
    with sqlite3.connect(truncation_store.path) as connection:
        connection.execute("DELETE FROM audit_log WHERE id = 2")
    tail_verification = truncation_store.verify_audit()
    with sqlite3.connect(truncation_store.path) as connection:
        connection.execute("DELETE FROM audit_log")
    empty_verification = truncation_store.verify_audit()
    truncation_passed = not tail_verification.valid and not empty_verification.valid
    controls.append(
        _control(
            "audit-checkpoint-truncation",
            truncation_passed,
            {
                "tail_delete_valid": tail_verification.valid,
                "full_delete_valid": empty_verification.valid,
            },
        )
    )
    return controls


def _metric_by_dimension(response: QueryResponse, dimension: str, metric: str) -> dict[str, Any]:
    return {str(row[dimension]): row[metric] for row in response.rows}


def _control(identifier: str, passed: bool, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": identifier,
        "expected": "PASS",
        "actual": "PASS" if passed else "FAIL",
        "passed": passed,
        "evidence": evidence,
    }


def _percentile(values: list[float], percentile: int) -> float:
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile / 100
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _write_artifacts(
    output_directory: Path,
    report: dict[str, Any],
    observations: list[dict[str, Any]],
    inputs: dict[str, str],
) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "benchmark.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output_directory / "observations.jsonl").open("w", encoding="utf-8") as stream:
        for observation in observations:
            stream.write(json.dumps(observation, sort_keys=True, separators=(",", ":")) + "\n")
    _write_query_csv(output_directory / "summary.csv", report["results"])
    _write_control_csv(output_directory / "controls.csv", report["controls"])
    (output_directory / "REPORT.md").write_text(_markdown(report), encoding="utf-8")
    (output_directory / "inputs.sha256").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(inputs.items())),
        encoding="utf-8",
    )
    artifact_names = (
        "REPORT.md",
        "benchmark.json",
        "controls.csv",
        "inputs.sha256",
        "observations.jsonl",
        "summary.csv",
    )
    (output_directory / "manifest.sha256").write_text(
        "".join(f"{_sha256(output_directory / name)}  {name}\n" for name in artifact_names),
        encoding="utf-8",
    )


def _write_query_csv(path: Path, cases: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            lineterminator="\n",
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


def _write_control_csv(path: Path, controls: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=("id", "expected", "actual", "passed", "evidence"),
            lineterminator="\n",
        )
        writer.writeheader()
        for control in controls:
            writer.writerow(
                {
                    **control,
                    "evidence": json.dumps(
                        control["evidence"], sort_keys=True, separators=(",", ":")
                    ),
                }
            )


def _markdown(report: dict[str, Any]) -> str:
    source = report["source"]
    lines = [
        "# Secure Data Clean Room benchmark",
        "",
        f"- Policy expectation accuracy: **{report['expectation_accuracy']:.1%}**",
        f"- Privacy/control accuracy: **{report['control_accuracy']:.1%}**",
        f"- Cases: **{report['cases']}** ({report['allowed_cases']} allow / "
        f"{report['denied_cases']} deny)",
        f"- Control checks: **{report['control_checks']}**",
        f"- Iterations per SQL case: **{report['iterations_per_case']}**",
        f"- Audit chain valid after run: **{str(report['audit_chain_valid']).lower()}**",
        f"- Source revision: `{source['revision']}` (dirty: `{str(source['dirty']).lower()}`)",
        f"- Source tree SHA-256: `{source['source_tree_sha256']}`",
        "",
        "## SQL policy corpus",
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
            "## Privacy and integrity controls",
            "",
            "| Control | Expected | Actual | Evidence |",
            "|---|---:|---:|---|",
        ]
    )
    for control in report["controls"]:
        evidence = json.dumps(control["evidence"], sort_keys=True, separators=(",", ":"))
        lines.append(
            f"| {control['id']} | {control['expected']} | {control['actual']} | `{evidence}` |"
        )
    lines.extend(
        [
            "",
            "Latencies cover local policy parsing, ledger operations, SQLite execution, privacy "
            "transformation, and audit append. They are not production throughput claims. "
            "`observations.jsonl` preserves every raw response envelope used for the SQL summary; "
            "`manifest.sha256` authenticates the generated evidence only after an independent "
            "reviewer trusts the repository and signing/distribution channel.",
            "",
        ]
    )
    return "\n".join(lines)


def _find_repository_root(start: Path) -> Path:
    for candidate in (start.resolve(), Path(__file__).resolve()):
        for parent in (candidate, *candidate.parents):
            if (parent / "pyproject.toml").is_file() and (parent / "uv.lock").is_file():
                return parent
    return Path(__file__).resolve().parents[2]


def _input_hashes(root: Path, corpus_path: Path, policy_path: Path) -> dict[str, str]:
    candidates = {
        _display_path(corpus_path, root): corpus_path,
        _display_path(policy_path, root): policy_path,
        "src/secure_data_clean_room/benchmark.py": root / "src/secure_data_clean_room/benchmark.py",
        "uv.lock": root / "uv.lock",
    }
    return {name: _sha256(path) for name, path in candidates.items() if path.is_file()}


def _source_metadata(root: Path) -> dict[str, Any]:
    revision = os.getenv("GITHUB_SHA") or _git_output(root, "rev-parse", "HEAD") or "unknown"
    status = _git_output(root, "status", "--porcelain", "--untracked-files=all")
    return {
        "revision": revision,
        "dirty": bool(status),
        "source_tree_sha256": _source_tree_hash(root),
        "uv_lock_sha256": _sha256_or_unknown(root / "uv.lock"),
        "benchmark_runner_sha256": _sha256_or_unknown(
            root / "src/secure_data_clean_room/benchmark.py"
        ),
    }


def _source_tree_hash(root: Path) -> str:
    paths = [root / "pyproject.toml", root / "uv.lock"]
    paths.extend(sorted((root / "src").rglob("*.py")))
    paths.extend(sorted((root / "fixtures").rglob("*.json")))
    digest = hashlib.sha256()
    for path in paths:
        if not path.is_file():
            continue
        relative = _display_path(path, root)
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _git_output(root: Path, *arguments: str) -> str | None:
    executable = shutil.which("git")
    if executable is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - resolved git plus fixed internal arguments.
            [executable, *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip()


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_or_unknown(path: Path) -> str:
    return _sha256(path) if path.is_file() else "unknown"
