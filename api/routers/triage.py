"""تعديل حالة الـ finding الموحّد ودرجة CVSS (مع تسجيل من غيّرها ومتى)."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api import schemas
from api.db import get_db
from api.models.audit import AuditLog
from api.models.correlation import CorrelatedFinding
from api.models.scan import FindingStatus
from api.services.cvss import base_score
from api.services.triage import can_transition, is_valid_status

router = APIRouter(tags=["triage"])


class TriageIn(BaseModel):
    status: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    actor: str = "analyst"


@router.post("/correlated/{finding_id}/triage", response_model=schemas.CorrelatedFindingOut)
def triage_finding(finding_id: int, payload: TriageIn, db: Session = Depends(get_db)):
    cf = db.get(CorrelatedFinding, finding_id)
    if not cf:
        raise HTTPException(404, "الـ finding غير موجود")

    # تغيير الحالة عبر آلة الحالات.
    if payload.status is not None:
        if not is_valid_status(payload.status):
            valid = ", ".join(s.value for s in FindingStatus)
            raise HTTPException(422, f"حالة غير صالحة: {payload.status} (المسموح: {valid})")
        if not can_transition(cf.status.value, payload.status):
            raise HTTPException(422, f"انتقال غير مسموح: {cf.status.value} → {payload.status}")
        cf.status = FindingStatus(payload.status)

    # تعديل CVSS يدويًا.
    if payload.cvss_vector is not None:
        try:
            cf.cvss_score = base_score(payload.cvss_vector)
        except (KeyError, ValueError):
            raise HTTPException(422, f"CVSS vector غير صالح: {payload.cvss_vector}")
        cf.cvss_vector = payload.cvss_vector
        cf.cvss_manual = True
    if payload.cvss_score is not None:
        cf.cvss_score = payload.cvss_score
        cf.cvss_manual = True

    db.add(
        AuditLog(
            action="triage",
            target_value=f"correlated:{cf.id}",
            program_id=cf.program_id,
            decision=cf.status.value,
            reason=f"cvss={cf.cvss_score}",
            actor=payload.actor,
        )
    )
    db.commit()
    db.refresh(cf)
    return cf
