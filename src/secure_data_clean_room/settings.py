from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .models import Principal


@dataclass(frozen=True, slots=True)
class Settings:
    policy_path: Path
    dataset_path: Path
    state_path: Path
    noise_key: bytes = field(repr=False)
    audit_key: bytes = field(repr=False)
    pseudonym_key: bytes = field(repr=False)
    api_principals: dict[str, Principal] = field(repr=False)

    @classmethod
    def from_environment(cls, root: Path | None = None) -> Settings:
        root = (root or Path.cwd()).resolve()
        demo_mode = os.getenv("CLEAN_ROOM_DEMO_MODE", "0") == "1"
        configured_policy = os.getenv("CLEAN_ROOM_POLICY")
        policy_path = (
            Path(configured_policy) if configured_policy is not None else _default_policy_path(root)
        )
        data_dir = Path(os.getenv("CLEAN_ROOM_DATA_DIR", root / "var"))
        api_principals = _api_principals(os.getenv("CLEAN_ROOM_API_KEYS"), demo_mode)
        return cls(
            policy_path=policy_path,
            dataset_path=Path(os.getenv("CLEAN_ROOM_DATASET", data_dir / "workforce.db")),
            state_path=Path(os.getenv("CLEAN_ROOM_STATE", data_dir / "state.db")),
            noise_key=_secret("CLEAN_ROOM_NOISE_KEY", demo_mode),
            audit_key=_secret("CLEAN_ROOM_AUDIT_KEY", demo_mode),
            pseudonym_key=_secret("CLEAN_ROOM_PSEUDONYM_KEY", demo_mode),
            api_principals=api_principals,
        )


def _default_policy_path(root: Path) -> Path:
    repository_policy = root / "fixtures/policy.json"
    if repository_policy.is_file():
        return repository_policy
    return Path(__file__).resolve().parent / "resources/policy.json"


def _secret(name: str, demo_mode: bool) -> bytes:
    value = os.getenv(name)
    if value is not None:
        encoded = value.encode()
        if len(encoded) < 32:
            raise ValueError(f"{name} must contain at least 32 UTF-8 bytes")
        return encoded
    if demo_mode:
        return hashlib.sha256(f"secure-data-clean-room-demo::{name}".encode()).digest()
    raise ValueError(f"{name} is required unless CLEAN_ROOM_DEMO_MODE=1")


def _api_principals(raw: str | None, demo_mode: bool) -> dict[str, Principal]:
    if raw is None:
        if not demo_mode:
            raise ValueError("CLEAN_ROOM_API_KEYS is required unless CLEAN_ROOM_DEMO_MODE=1")
        raw = json.dumps(
            {
                "demo-analyst-key": {"subject": "demo.analyst", "role": "analyst"},
                "demo-auditor-key": {"subject": "demo.auditor", "role": "auditor"},
                "demo-privacy-key": {
                    "subject": "demo.privacy-officer",
                    "role": "privacy_officer",
                },
            }
        )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("CLEAN_ROOM_API_KEYS must be a JSON object") from error
    if not isinstance(payload, dict) or not payload:
        raise ValueError("CLEAN_ROOM_API_KEYS must contain at least one key")
    principals: dict[str, Principal] = {}
    for token, principal_payload in payload.items():
        if not isinstance(token, str) or len(token) < 16:
            raise ValueError("each API token must contain at least 16 characters")
        principals[token] = Principal.model_validate(principal_payload)
    return principals
