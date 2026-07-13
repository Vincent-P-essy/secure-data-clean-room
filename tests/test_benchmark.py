from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_data_clean_room.benchmark import _percentile, run_benchmark
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
    assert report["cases"] == 14
    assert report["audit_chain_valid"] is True
    assert (output / "BENCHMARK.md").is_file()
    assert (output / "benchmark.csv").is_file()
    persisted = json.loads((output / "benchmark.json").read_text(encoding="utf-8"))
    assert persisted["corpus_sha256"] == report["corpus_sha256"]


def test_benchmark_rejects_invalid_controls(settings: Settings, tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="non-empty"):
        run_benchmark(settings, corpus_path=empty, output_directory=tmp_path, iterations=1)
    with pytest.raises(ValueError, match="iterations"):
        run_benchmark(settings, corpus_path=empty, output_directory=tmp_path, iterations=0)
    assert _percentile([2.5], 95) == 2.5
    assert _percentile([1, 3], 50) == 2
