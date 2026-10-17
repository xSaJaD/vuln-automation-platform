"""تشغيل الفحص (nuclei) وعرض النتائج (findings)."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api import schemas
from api.db import get_db
from api.models.program import Program
from api.models.scan import Finding, ScanRun

router = APIRouter(tags=["scan"])


@router.post("/programs/{program_id}/scan")
def trigger_scan(program_id: int, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")

    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("scan.run_nuclei", args=[program_id])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")

    return {"status": "queued", "task_id": task.id}


@router.get("/programs/{program_id}/findings", response_model=list[schemas.FindingOut])
def list_findings(program_id: int, db: Session = Depends(get_db)):
    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")
    stmt = (
        select(Finding)
        .join(ScanRun, Finding.scan_run_id == ScanRun.id)
        .where(ScanRun.program_id == program_id)
        .order_by(Finding.id.desc())
    )
    return list(db.scalars(stmt))
