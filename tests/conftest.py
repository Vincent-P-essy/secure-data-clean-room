from __future__ import annotations

from pathlib import Path

import pytest

from secure_data_clean_room.models import Principal, Role
from secure_data_clean_room.service import CleanRoomService
from secure_data_clean_room.settings import Settings


@pytest.fixture
def repository_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def settings(tmp_path: Path, repository_root: Path) -> Settings:
    return Settings(
        policy_path=repository_root / "fixtures/policy.json",
        dataset_path=tmp_path / "workforce.db",
        state_path=tmp_path / "state.db",
        noise_key=b"noise-key-for-tests-is-at-least-32-bytes",
        audit_key=b"audit-key-for-tests-is-at-least-32-bytes",
        pseudonym_key=b"pseudonym-key-for-tests-at-least-32-bytes",
        api_principals={
            "test-analyst-key-0001": Principal(subject="test.analyst", role=Role.ANALYST),
            "test-auditor-key-0001": Principal(subject="test.auditor", role=Role.AUDITOR),
            "test-privacy-key-0001": Principal(subject="test.privacy", role=Role.PRIVACY_OFFICER),
        },
    )


@pytest.fixture
def service(settings: Settings) -> CleanRoomService:
    instance = CleanRoomService(settings)
    instance.initialize_demo()
    return instance


@pytest.fixture
def analyst() -> Principal:
    return Principal(subject="unit.analyst", role=Role.ANALYST)
