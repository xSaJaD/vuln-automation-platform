"""توليد مسودّات التقارير. لا إرسال آلي إلى HackerOne."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.config import settings
from api.db import get_db
from api.models.audit import AuditLog
from api.models.correlation import CorrelatedFinding
from api.models.program import Program
from api.models.scan import FindingStatus
from api.services.report_generator import render_report, save_report

router = APIRouter(tags=["report"])


@router.post("/correlated/{finding_id}/report")
def generate_report(finding_id: int, save: bool = True, db: Session = Depends(get_db)):
    cf = db.get(CorrelatedFinding, finding_id)
    if not cf:
        raise HTTPException(404, "الـ finding غير موجود")

    # لا يُولَّد تقرير إلا لـ finding راجعه الباحث وأكّده (انضباط سير العمل).
    if cf.status != FindingStatus.confirmed:
        raise HTTPException(
            409,
            f"لا يُولَّد تقرير إلا لـ finding مؤكَّد (الحالة الحالية: {cf.status.value}). "
            "راجِعها وأكّدها أولًا عبر /triage.",
        )

    program = db.get(Program, cf.program_id)
    markdown = render_report(cf, program)

    saved_to = None
    if save:
        saved_to = save_report(settings.reports_out_dir, program, cf, markdown)

    db.add(
        AuditLog(
            action="report_draft",
            target_value=f"correlated:{cf.id}",
            program_id=cf.program_id,
            decision="draft",
            reason=saved_to or "returned-only",
            actor="system",
        )
    )
    db.commit()

    return {"finding_id": cf.id, "draft": True, "saved_to": saved_to, "markdown": markdown}
