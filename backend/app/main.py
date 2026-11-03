import os
from collections import deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from app.api.routes import router
from app.core.body_limit import BodyLimitMiddleware
from app.core.config import Settings, get_settings
from app.models.database import Scan, sessions


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    app = FastAPI(
        title="RepoSentinel AI",
        version="0.1.0",
        description="Single-owner source security triage. All /api/v1 routes require a bearer token. Repository code is never executed.",
    )
    app.add_middleware(BodyLimitMiddleware, settings=settings)
    app.state.settings = settings
    app.state.sessions = sessions(settings.database_url)
    app.state.rate_events = deque()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        length = request.headers.get("content-length", "0")
        try:
            too_large = int(length) > settings.max_archive_bytes + 1024
        except ValueError:
            return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
        if too_large:
            return JSONResponse({"detail": "Request too large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        if not request.url.path.startswith(("/docs", "/redoc")):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
            )
        return response

    @app.get("/health", tags=["system"])
    def health():
        try:
            with app.state.sessions() as session:
                session.execute(select(Scan.id).limit(1))
            return {
                "status": "ok",
                "version": "0.1.0",
                "revision": os.getenv("RENDER_GIT_COMMIT", "local"),
                "demo_mode": settings.demo_mode,
            }
        except Exception:
            return JSONResponse(
                {"status": "unready", "detail": "Database unavailable or migrations not applied"},
                status_code=503,
            )

    app.include_router(router)
    if settings.frontend_dir.is_dir():
        app.mount("/", StaticFiles(directory=settings.frontend_dir, html=True), name="dashboard")
    return app


app = create_app()
