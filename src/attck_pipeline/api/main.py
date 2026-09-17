from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from attck_pipeline.config import Settings
from attck_pipeline.db.motor_setup import close_motor, init_motor


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_motor(Settings())
    yield
    await close_motor()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Liszt ATT&CK Pipeline API",
        version="0.1.0",
        lifespan=lifespan,
    )

    from attck_pipeline.api.routers import (
        diffs,
        findings,
        ingest,
        overlay,
        releases,
        reports,
        scenarios,
    )

    app.include_router(releases.router, prefix="/releases", tags=["releases"])
    app.include_router(ingest.router, tags=["ingest"])
    app.include_router(diffs.router, prefix="/diffs", tags=["diffs"])
    app.include_router(findings.router, prefix="/findings", tags=["findings"])
    app.include_router(scenarios.router, prefix="/scenarios", tags=["scenarios"])
    app.include_router(reports.router, prefix="/reports", tags=["reports"])
    app.include_router(overlay.router, prefix="/overlay", tags=["overlay"])

    return app


app = create_app()
