from __future__ import annotations

import argparse
import json
from pathlib import Path

import uvicorn

from .api import create_app
from .benchmark import run_benchmark
from .models import Principal, QueryRequest, Role
from .service import CleanRoomService
from .settings import Settings


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="clean-room")
    root.add_argument("--root", type=Path, default=Path.cwd(), help="repository/configuration root")
    commands = root.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init-demo", help="create the synthetic demo dataset")
    initialize.add_argument("--rows", type=int, default=180)

    query = commands.add_parser("query", help="submit an aggregate query")
    query.add_argument("--sql", required=True)
    query.add_argument("--epsilon", type=float)
    query.add_argument("--subject", default="cli.analyst")

    explain = commands.add_parser(
        "explain", help="explain and rewrite a query without executing it"
    )
    explain.add_argument("--sql", required=True)
    explain.add_argument("--subject", default="cli.analyst")

    commands.add_parser("verify-audit", help="verify every link in the audit chain")

    benchmark = commands.add_parser("benchmark", help="run the versioned adversarial corpus")
    benchmark.add_argument("--corpus", type=Path, default=Path("fixtures/corpus/queries.json"))
    benchmark.add_argument("--out", type=Path, default=Path("reports"))
    benchmark.add_argument("--iterations", type=int, default=10)

    serve = commands.add_parser("serve", help="start the API and dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    return root


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    settings = Settings.from_environment(arguments.root)
    service = CleanRoomService(settings)
    if arguments.command == "init-demo":
        service.initialize_demo(rows=arguments.rows)
        print(json.dumps({"dataset": str(settings.dataset_path), "rows": arguments.rows}))
        return 0
    if arguments.command in {"query", "explain"}:
        principal = Principal(subject=arguments.subject, role=Role.ANALYST)
        request = QueryRequest(sql=arguments.sql, epsilon=getattr(arguments, "epsilon", None))
        query_result = (
            service.query(request, principal)
            if arguments.command == "query"
            else service.explain(request, principal)
        )
        print(query_result.model_dump_json(indent=2))
        return 0 if query_result.decision.value == "ALLOW" else 2
    if arguments.command == "verify-audit":
        audit_result = service.state.verify_audit()
        print(audit_result.model_dump_json(indent=2))
        return 0 if audit_result.valid else 3
    if arguments.command == "benchmark":
        report = run_benchmark(
            settings,
            corpus_path=arguments.corpus,
            output_directory=arguments.out,
            iterations=arguments.iterations,
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return (
            0
            if report["expectation_accuracy"] == 1.0
            and report["control_accuracy"] == 1.0
            and report["audit_chain_valid"]
            else 4
        )
    if arguments.command == "serve":
        uvicorn.run(create_app(settings), host=arguments.host, port=arguments.port)
        return 0
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
