"""نقطة دخول FastAPI.

Phase 0: health check.
Phase 1: نماذج البيانات + CRUD للبرامج والنطاق.
Phase 2: Scope Gatekeeper يحرس إنشاء الأهداف.
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse

from api import __version__
from api.db import init_db
from api.routers import (
    correlate,
    pipeline,
    programs,
    recon,
    report,
    scan,
    strix,
    targets,
    triage,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # راحة تطوير — الإنتاج يطبّق المخطط عبر Alembic.
    init_db()
    yield


app = FastAPI(
    title="vuln-automation-platform",
    version=__version__,
    description="منصة self-hosted لأتمتة فحص الثغرات ضمن نطاق مصرّح به فقط.",
    lifespan=lifespan,
)

app.include_router(programs.router)
app.include_router(targets.router)
app.include_router(recon.router)
app.include_router(scan.router)
app.include_router(strix.router)
app.include_router(correlate.router)
app.include_router(triage.router)
app.include_router(report.router)
app.include_router(pipeline.router)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


_DASHBOARD = os.path.join(os.path.dirname(__file__), "static", "index.html")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/dashboard")


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(_DASHBOARD)
