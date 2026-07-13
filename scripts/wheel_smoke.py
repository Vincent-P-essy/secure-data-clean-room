from __future__ import annotations

import os
import tempfile
from pathlib import Path

from secure_data_clean_room import __version__
from secure_data_clean_room.api import create_app
from secure_data_clean_room.models import Decision, Principal, QueryRequest, Role
from secure_data_clean_room.service import CleanRoomService
from secure_data_clean_room.settings import Settings


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="clean-room-wheel-smoke-") as temporary:
        root = Path(temporary)
        os.chdir(root)
        os.environ["CLEAN_ROOM_DEMO_MODE"] = "1"
        os.environ["CLEAN_ROOM_DATA_DIR"] = str(root / "data")
        settings = Settings.from_environment()
        if not settings.policy_path.is_file() or "resources" not in settings.policy_path.parts:
            raise RuntimeError("installed wheel did not provide its default policy resource")

        service = CleanRoomService(settings)
        service.initialize_demo()
        response = service.query(
            QueryRequest(sql="SELECT COUNT(*) AS total FROM employees"),
            Principal(subject="wheel.smoke", role=Role.ANALYST),
        )
        if response.decision is not Decision.ALLOW or not response.rows:
            raise RuntimeError("installed wheel could not execute a protected aggregate")

        route_paths = {route.path for route in create_app(settings).routes}
        if "/" not in route_paths or "/assets" not in route_paths:
            raise RuntimeError("installed wheel did not provide dashboard resources")
        print(f"secure-data-clean-room {__version__} wheel smoke: ok")


if __name__ == "__main__":
    main()
