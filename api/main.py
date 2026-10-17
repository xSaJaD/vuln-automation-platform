"""نقطة دخول FastAPI.

Phase 0: API فارغ يرد فقط على health check. لا منطق فحص أو recon بعد.
"""

from fastapi import FastAPI

from api import __version__

app = FastAPI(
    title="vuln-automation-platform",
    version=__version__,
    description="منصة self-hosted لأتمتة فحص الثغرات ضمن نطاق مصرّح به فقط.",
)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    """فحص صحة بسيط يستخدمه docker-compose و uptime checks."""
    return {"status": "ok", "version": __version__}
