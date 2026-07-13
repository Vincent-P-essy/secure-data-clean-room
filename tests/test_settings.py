from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_data_clean_room.models import Role
from secure_data_clean_room.settings import Settings


def test_demo_settings_are_explicit_and_deterministic(
    monkeypatch: pytest.MonkeyPatch, repository_root: Path
) -> None:
    monkeypatch.setenv("CLEAN_ROOM_DEMO_MODE", "1")
    settings = Settings.from_environment(repository_root)
    repeated = Settings.from_environment(repository_root)
    assert settings.noise_key == repeated.noise_key
    assert settings.api_principals["demo-analyst-key"].role is Role.ANALYST
    assert "demo-analyst-key" not in repr(settings)


def test_production_settings_require_secrets(
    monkeypatch: pytest.MonkeyPatch, repository_root: Path
) -> None:
    for name in (
        "CLEAN_ROOM_DEMO_MODE",
        "CLEAN_ROOM_NOISE_KEY",
        "CLEAN_ROOM_AUDIT_KEY",
        "CLEAN_ROOM_PSEUDONYM_KEY",
        "CLEAN_ROOM_API_KEYS",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="API_KEYS"):
        Settings.from_environment(repository_root)


def test_production_settings_parse_keys_and_validate_lengths(
    monkeypatch: pytest.MonkeyPatch, repository_root: Path
) -> None:
    monkeypatch.setenv(
        "CLEAN_ROOM_API_KEYS",
        json.dumps({"a-production-token": {"subject": "prod.analyst", "role": "analyst"}}),
    )
    monkeypatch.setenv("CLEAN_ROOM_NOISE_KEY", "n" * 32)
    monkeypatch.setenv("CLEAN_ROOM_AUDIT_KEY", "a" * 32)
    monkeypatch.setenv("CLEAN_ROOM_PSEUDONYM_KEY", "p" * 32)
    settings = Settings.from_environment(repository_root)
    assert settings.api_principals["a-production-token"].subject == "prod.analyst"

    monkeypatch.setenv("CLEAN_ROOM_NOISE_KEY", "weak")
    with pytest.raises(ValueError, match="32"):
        Settings.from_environment(repository_root)


def test_invalid_api_key_json_is_rejected(
    monkeypatch: pytest.MonkeyPatch, repository_root: Path
) -> None:
    monkeypatch.setenv("CLEAN_ROOM_API_KEYS", "not-json")
    with pytest.raises(ValueError, match="JSON object"):
        Settings.from_environment(repository_root)
