import hmac
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request
from starlette.responses import Response

from .models import (
    AuditVerification,
    BudgetSnapshot,
    ExplainResponse,
    HealthResponse,
    Principal,
    QueryRequest,
    QueryResponse,
    Role,
)
from .service import CleanRoomService
from .settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or Settings.from_environment()
    service = CleanRoomService(resolved)
    if os.getenv("CLEAN_ROOM_AUTO_INIT", "0") == "1" and not resolved.dataset_path.exists():
        service.initialize_demo()

    app = FastAPI(
        title="Secure Data Clean Room",
        version="0.1.0",
        description="Policy-constrained aggregate analysis; raw rows are never returned.",
    )
    app.state.service = service
    app.state.settings = resolved

    def authenticate(x_api_key: Annotated[str | None, Header()] = None) -> Principal:
        if x_api_key is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing X-API-Key")
        for expected, principal in resolved.api_principals.items():
            if hmac.compare_digest(x_api_key, expected):
                return principal
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid X-API-Key")

    def control_reader(principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
        if principal.role not in {Role.AUDITOR, Role.PRIVACY_OFFICER}:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "control-plane role required")
        return principal

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/healthz", response_model=HealthResponse)
    def health() -> HealthResponse:
        return HealthResponse(
            dataset=service.policy.dataset, dataset_version=service.policy.dataset_version
        )

    @app.post("/v1/query", response_model=QueryResponse)
    def query(
        request: QueryRequest, principal: Annotated[Principal, Depends(authenticate)]
    ) -> QueryResponse:
        return service.query(request, principal)

    @app.post("/v1/policy/explain", response_model=ExplainResponse)
    def explain(
        request: QueryRequest, principal: Annotated[Principal, Depends(authenticate)]
    ) -> ExplainResponse:
        return service.explain(request, principal)

    @app.get("/v1/budget", response_model=BudgetSnapshot)
    def budget(
        principal: Annotated[Principal, Depends(authenticate)],
    ) -> BudgetSnapshot:
        return service.state.budget(principal.subject, service.policy.principal_budget)

    @app.get("/v1/audit/verify", response_model=AuditVerification)
    def verify_audit(
        _principal: Annotated[Principal, Depends(control_reader)],
    ) -> AuditVerification:
        return service.state.verify_audit()

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics(_principal: Annotated[Principal, Depends(control_reader)]) -> str:
        verification = service.state.verify_audit()
        valid = 1 if verification.valid else 0
        return (
            "# HELP clean_room_audit_chain_valid Whether the HMAC audit chain verifies.\n"
            "# TYPE clean_room_audit_chain_valid gauge\n"
            f"clean_room_audit_chain_valid {valid}\n"
            "# HELP clean_room_audit_entries Number of audit entries verified.\n"
            "# TYPE clean_room_audit_entries gauge\n"
            f"clean_room_audit_entries {verification.entries_checked}\n"
        )

    web_root = Path(__file__).resolve().parents[2] / "web"
    if web_root.is_dir():
        app.mount("/assets", StaticFiles(directory=web_root), name="assets")

        @app.get("/", include_in_schema=False)
        def dashboard() -> FileResponse:
            return FileResponse(web_root / "index.html")

    return app


def app_from_environment() -> FastAPI:
    return create_app()
