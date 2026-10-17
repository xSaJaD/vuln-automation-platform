"""مهام Celery — أغلفة رفيعة حول منطق الـ recon."""

from __future__ import annotations

from workers import tools
from workers.recon_logic import ReconTools, run_full_recon

# يُستورد celery_app بشكل كسول داخل الدالة لتجنّب دورة الاستيراد عند التسجيل.
from workers.celery_app import celery_app  # noqa: E402

DEFAULT_TOOLS = ReconTools(
    subfinder=tools.run_subfinder,
    httpx=tools.run_httpx,
    naabu=tools.run_naabu,
)


@celery_app.task(name="recon.run_full")
def recon_run_full(program_id: int, seed: str) -> dict:
    """يشغّل السلسلة الكاملة لبرنامج وبذرة. البذرة يُفترض أنها مرّت الحارس مسبقًا."""
    from api.db import SessionLocal
    from api.models.program import Program

    db = SessionLocal()
    try:
        program = db.get(Program, program_id)
        if program is None:
            return {"error": "program not found", "program_id": program_id}
        hosts = run_full_recon(db, program, seed, DEFAULT_TOOLS)
        return {
            "program_id": program_id,
            "seed": seed,
            "hosts_total": len(hosts),
            "in_scope": sum(1 for h in hosts if h.in_scope),
            "live": sum(1 for h in hosts if h.is_live),
        }
    finally:
        db.close()
