"""نقطة دخول FastAPI.

Phase 0: health check.
Phase 1: نماذج البيانات + CRUD للبرامج والنطاق.
Phase 2: Scope Gatekeeper يحرس إنشاء الأهداف.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from api import __version__
from api.db import init_db
from api.routers import programs, recon, scan, targets


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


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
