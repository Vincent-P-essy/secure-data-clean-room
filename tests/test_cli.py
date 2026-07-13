from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_data_clean_room import cli


def test_cli_end_to_end(
    monkeypatch: pytest.MonkeyPatch,
    repository_root: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("CLEAN_ROOM_DEMO_MODE", "1")
    monkeypatch.setenv("CLEAN_ROOM_DATA_DIR", str(tmp_path / "var"))
    base = ["--root", str(repository_root)]

    assert cli.main([*base, "init-demo", "--rows", "180"]) == 0
    initialized = json.loads(capsys.readouterr().out)
    assert initialized["rows"] == 180

    assert (
        cli.main(
            [
                *base,
                "query",
                "--sql",
                "SELECT department, AVG(salary) FROM employees GROUP BY department",
            ]
        )
        == 0
    )
    assert '"decision": "ALLOW"' in capsys.readouterr().out

    assert cli.main([*base, "query", "--sql", "SELECT salary FROM employees"]) == 2
    assert '"decision": "DENY"' in capsys.readouterr().out

    assert (
        cli.main(
            [
                *base,
                "explain",
                "--sql",
                "SELECT COUNT(*) AS total FROM employees",
            ]
        )
        == 0
    )
    assert "PARAMETERIZED_QUERY_REBUILT" in capsys.readouterr().out
    assert cli.main([*base, "verify-audit"]) == 0
    assert '"valid": true' in capsys.readouterr().out

    output = tmp_path / "benchmark"
    assert (
        cli.main(
            [
                *base,
                "benchmark",
                "--corpus",
                str(repository_root / "fixtures/corpus/queries.json"),
                "--out",
                str(output),
                "--iterations",
                "1",
            ]
        )
        == 0
    )
    assert (output / "benchmark.json").is_file()
    capsys.readouterr()


def test_cli_serve_uses_requested_binding(
    monkeypatch: pytest.MonkeyPatch, repository_root: Path, tmp_path: Path
) -> None:
    monkeypatch.setenv("CLEAN_ROOM_DEMO_MODE", "1")
    monkeypatch.setenv("CLEAN_ROOM_DATA_DIR", str(tmp_path / "var"))
    observed: dict[str, object] = {}

    def fake_run(app: object, *, host: str, port: int) -> None:
        observed.update({"app": app, "host": host, "port": port})

    monkeypatch.setattr(cli.uvicorn, "run", fake_run)
    assert (
        cli.main(
            [
                "--root",
                str(repository_root),
                "serve",
                "--host",
                "127.0.0.2",
                "--port",
                "9090",
            ]
        )
        == 0
    )
    assert observed["host"] == "127.0.0.2" and observed["port"] == 9090
