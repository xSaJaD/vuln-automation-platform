"""تشغيل محرك Strix على هدف ضمن النطاق."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db import get_db
from api.models.program import Program
from api.services.scope_gatekeeper import check_target

router = APIRouter(tags=["strix"])


class StrixIn(BaseModel):
    target: str                      # رابط ويب / repo / OpenAPI spec ضمن النطاق
    instruction: str | None = None   # تعليمات grey-box اختيارية


@router.post("/programs/{program_id}/strix")
def trigger_strix(program_id: int, payload: StrixIn, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")

    decision = check_target(db, program, payload.target, actor="strix-trigger")
    if not decision.allowed:
        raise HTTPException(403, f"الهدف خارج النطاق — لا يبدأ Strix: {decision.reason}")

    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task(
            "strix.run", args=[program_id, payload.target, payload.instruction]
        )
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")

    return {"status": "queued", "task_id": task.id, "target": payload.target}
