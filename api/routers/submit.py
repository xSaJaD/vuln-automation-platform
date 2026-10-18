"""فحص التكرار وإرسال مسودة إلى HackerOne (بموافقة صريحة فقط)."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.config import settings
from api.db import get_db
from api.models.audit import AuditLog
from api.models.correlation import CorrelatedFinding
from api.models.program import Program
from api.models.scan import FindingStatus
from api.services.report_generator import render_report

router = APIRouter(tags=["submit"])


class SubmitIn(BaseModel):
    confirm: bool = False


@router.post("/programs/{program_id}/check-duplicates")
def check_duplicates(program_id: int, db: Session = Depends(get_db)):
    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")
    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("dup.check", args=[program_id])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")
    return {"status": "queued", "task_id": task.id}


@router.post("/correlated/{finding_id}/submit")
def submit_finding(finding_id: int, payload: SubmitIn, db: Session = Depends(get_db)):
    cf = db.get(CorrelatedFinding, finding_id)
    if not cf:
        raise HTTPException(404, "الـ finding غير موجود")

    # لا إرسال آلي: يتطلب حالة مؤكّدة + موافقة صريحة في كل مرة.
    if cf.status != FindingStatus.confirmed:
        raise HTTPException(409, f"لا يُرسَل إلا finding مؤكَّد (الحالة: {cf.status.value})")
    if not payload.confirm:
        raise HTTPException(400, "الإرسال يتطلب موافقة صريحة: confirm=true")
    if not (settings.hackerone_api_username and settings.hackerone_api_token):
        raise HTTPException(503, "مفاتيح HackerOne غير مهيّأة")

    program = db.get(Program, cf.program_id)
    body = render_report(cf, program)
    title = f"[{cf.severity}] {cf.vuln_type} on {cf.host}"

    from workers import hackerone

    try:
        result = hackerone.submit_report(title, body, program.handle, cf.severity)
    except Exception as exc:
        raise HTTPException(502, f"فشل الإرسال إلى HackerOne: {exc}")

    cf.status = FindingStatus.reported
    cf.submitted_ref = result.get("url") or result.get("id")
    db.add(
        AuditLog(
            action="report_submit",
            target_value=f"correlated:{cf.id}",
            program_id=cf.program_id,
            decision="submitted",
            reason=cf.submitted_ref or "",
            actor="human",
        )
    )
    db.commit()
    db.refresh(cf)
    return {"finding_id": cf.id, "status": cf.status.value, "submitted_ref": cf.submitted_ref}
