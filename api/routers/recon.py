"""تشغيل الـ recon وعرض نتائجه.

البذرة تمر عبر Scope Gatekeeper قبل جدولة أي مهمة — لا recon لبذرة خارج النطاق.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api import schemas
from api.db import get_db
from api.models.program import Program
from api.models.recon import Host
from api.services.scope_gatekeeper import check_target

router = APIRouter(tags=["recon"])


class ReconIn(BaseModel):
    seed: str  # نطاق جذر ضمن النطاق، مثل example.com


@router.post("/programs/{program_id}/recon")
def trigger_recon(program_id: int, payload: ReconIn, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")

    decision = check_target(db, program, payload.seed, actor="recon-trigger")
    if not decision.allowed:
        raise HTTPException(403, f"البذرة خارج النطاق — لا يبدأ recon: {decision.reason}")

    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("recon.run_full", args=[program_id, payload.seed])
    except Exception as exc:  # الطابور غير متاح (Redis/Celery غير مشغّل)
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")

    return {"status": "queued", "task_id": task.id, "seed": payload.seed}


@router.get("/programs/{program_id}/hosts", response_model=list[schemas.HostOut])
def list_hosts(program_id: int, db: Session = Depends(get_db)):
    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")
    return list(db.scalars(select(Host).where(Host.program_id == program_id)))
