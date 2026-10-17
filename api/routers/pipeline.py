"""تشغيل الـ pipeline الكامل (recon → scan → correlate) لهدف ضمن النطاق."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db import get_db
from api.models.program import Program
from api.services.scope_gatekeeper import check_target

router = APIRouter(tags=["pipeline"])


class PipelineIn(BaseModel):
    seed: str  # نطاق جذر ضمن النطاق


@router.post("/programs/{program_id}/pipeline")
def trigger_pipeline(program_id: int, payload: PipelineIn, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")

    decision = check_target(db, program, payload.seed, actor="pipeline-trigger")
    if not decision.allowed:
        raise HTTPException(403, f"البذرة خارج النطاق — لا يبدأ pipeline: {decision.reason}")

    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("pipeline.run_full", args=[program_id, payload.seed])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")

    return {"status": "queued", "task_id": task.id, "seed": payload.seed}
