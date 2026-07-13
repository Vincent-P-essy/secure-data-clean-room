from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secure_data_clean_room.benchmark import (
    _display_path,
    _percentile,
    _sha256_or_unknown,
    _source_tree_hash,
    _validate_corpus,
    run_benchmark,
)
from secure_data_clean_room.settings import Settings


def test_benchmark_evaluates_versioned_corpus(
    settings: Settings, repository_root: Path, tmp_path: Path
) -> None:
    output = tmp_path / "reports"
    report = run_benchmark(
        settings,
        corpus_path=repository_root / "fixtures/corpus/queries.json",
        output_directory=output,
        iterations=2,
    )
    assert report["expectation_accuracy"] == 1.0
    assert report["control_accuracy"] == 1.0
    assert report["control_checks"] == 5
    assert report["cases"] == 14
    assert report["audit_chain_valid"] is True
    assert (output / "REPORT.md").is_file()
    assert (output / "summary.csv").is_file()
    assert (output / "controls.csv").is_file()
    assert len((output / "observations.jsonl").read_text(encoding="utf-8").splitlines()) == 28
    persisted = json.loads((output / "benchmark.json").read_text(encoding="utf-8"))
    assert persisted["corpus_sha256"] == report["corpus_sha256"]
    assert persisted["source"]["uv_lock_sha256"] != "unknown"
    for line in (output / "manifest.sha256").read_text(encoding="utf-8").splitlines():
        expected, name = line.split("  ", maxsplit=1)
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected


def test_benchmark_rejects_invalid_controls(settings: Settings, tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="non-empty"):
        run_benchmark(settings, corpus_path=empty, output_directory=tmp_path, iterations=1)
    with pytest.raises(ValueError, match="iterations"):
        run_benchmark(settings, corpus_path=empty, output_directory=tmp_path, iterations=0)
    assert _percentile([2.5], 95) == 2.5
    assert _percentile([1, 3], 50) == 2


@pytest.mark.parametrize(
    "payload",
    [
        {},
        ["not-an-object"],
        [{"id": "case", "expected": "ALLOW", "sql": "SELECT 1", "unknown": True}],
        [{"expected": "ALLOW", "sql": "SELECT 1"}],
        [
            {"id": "same", "expected": "ALLOW", "sql": "SELECT 1"},
            {"id": "same", "expected": "DENY", "sql": "SELECT 2"},
        ],
        [{"id": "case", "expected": "ALLOW", "sql": ""}],
        [{"id": "case", "expected": None, "sql": "SELECT 1"}],
        [{"id": "case", "expected": "MAYBE", "sql": "SELECT 1"}],
        [{"id": "case", "expected": "ALLOW", "sql": "SELECT 1", "epsilon": 0}],
    ],
)
def test_benchmark_corpus_schema_fails_closed(payload: object) -> None:
    with pytest.raises(ValueError):
        _validate_corpus(payload)


def test_source_hash_helpers_cover_external_and_missing_paths(tmp_path: Path) -> None:
    external = tmp_path / "outside.txt"
    external.write_text("evidence", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    assert _display_path(external, root) == external.as_posix()
    assert len(_source_tree_hash(root)) == 64
    assert _sha256_or_unknown(root / "missing") == "unknown"
