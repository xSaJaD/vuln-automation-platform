"""نقطة دخول FastAPI.

Phase 0: health check.
Phase 1: نماذج البيانات + CRUD للبرامج والنطاق.
Phase 2: Scope Gatekeeper يحرس إنشاء الأهداف.
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from api import __version__
from api.config import settings
from api.db import init_db
from api.routers import (
    correlate,
    credentials,
    pipeline,
    programs,
    recon,
    report,
    scan,
    strix,
    submit,
    targets,
    triage,
)
from api.services.ratelimit import RateLimiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.log_json:
        from api.logging_config import setup_logging

        setup_logging(settings.log_level)
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
app.include_router(credentials.router)
app.include_router(submit.router)


_limiter = RateLimiter(settings.rate_limit_per_minute)
_RL_EXEMPT = {"/", "/dashboard", "/health", "/health/workers"}


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if settings.rate_limit_enabled and request.url.path not in _RL_EXEMPT:
        host = request.client.host if request.client else "?"
        if not _limiter.allow(host):
            return JSONResponse({"detail": "تجاوزت حد الطلبات، حاول بعد قليل"}, status_code=429)
    return await call_next(request)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/health/workers", tags=["meta"])
def workers_health():
    """حالة عمّال Celery (أي العمّال ردّوا على ping)."""
    try:
        from workers.celery_app import celery_app

        ping = celery_app.control.inspect(timeout=1).ping() or {}
    except Exception:
        ping = {}
    return {"workers": list(ping.keys()), "count": len(ping)}


_DASHBOARD = os.path.join(os.path.dirname(__file__), "static", "index.html")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/dashboard")


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse(_DASHBOARD)
