"""تشغيل الدمج وعرض الـ findings الموحّدة."""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from api import schemas
from api.db import get_db
from api.models.audit import AuditLog
from api.models.correlation import CorrelatedFinding
from api.models.program import Program
from workers.correlation_logic import correlate

router = APIRouter(tags=["correlate"])


@router.post("/programs/{program_id}/correlate", response_model=list[schemas.CorrelatedFindingOut])
def run_correlation(program_id: int, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")
    # الدمج عملية حتمية على بيانات القاعدة — تُنفَّذ مباشرة (لا تحتاج worker).
    return correlate(db, program)


@router.get("/programs/{program_id}/correlated", response_model=list[schemas.CorrelatedFindingOut])
def list_correlated(program_id: int, db: Session = Depends(get_db)):
    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")
    stmt = (
        select(CorrelatedFinding)
        .where(CorrelatedFinding.program_id == program_id)
        .order_by(CorrelatedFinding.id.desc())
    )
    return list(db.scalars(stmt))


@router.post("/programs/{program_id}/confirm")
def trigger_confirm(program_id: int, db: Session = Depends(get_db)):
    """تأكيد نشط لكل النتائج — يرسل طلبات تحقّق فعلية ويحدّث الحالة/الثقة."""
    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")
    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("confirm.run", args=[program_id])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")
    return {"status": "queued", "task_id": task.id}


@router.delete("/programs/{program_id}/results", status_code=204)
def delete_all_results(program_id: int, actor: str = "dashboard", db: Session = Depends(get_db)):
    """يحذف كل نتائج البرنامج دفعة واحدة (موحّدة + خام + جولات فحص + مضيفات)."""
    from api.models.recon import Host
    from api.models.scan import Finding, ScanRun

    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")

    n = db.query(CorrelatedFinding).filter_by(program_id=program_id).count()
    db.query(CorrelatedFinding).filter_by(program_id=program_id).delete()
    sr_ids = [r.id for r in db.query(ScanRun).filter_by(program_id=program_id).all()]
    if sr_ids:
        db.query(Finding).filter(Finding.scan_run_id.in_(sr_ids)).delete(synchronize_session=False)
    db.query(ScanRun).filter_by(program_id=program_id).delete()
    db.query(Host).filter_by(program_id=program_id).delete()
    db.add(
        AuditLog(
            action="delete_all_results",
            target_value=f"program:{program_id}",
            program_id=program_id,
            decision="deleted",
            reason=f"count={n}",
            actor=actor,
        )
    )
    db.commit()
    return Response(status_code=204)


@router.delete("/correlated/{finding_id}", status_code=204)
def delete_correlated(finding_id: int, actor: str = "dashboard", db: Session = Depends(get_db)):
    """يحذف نتيجة موحّدة (مثلًا false-positive). يُسجَّل الحذف في audit_log."""
    cf = db.get(CorrelatedFinding, finding_id)
    if not cf:
        raise HTTPException(404, "الـ finding غير موجود")
    db.add(
        AuditLog(
            action="delete_finding",
            target_value=f"correlated:{cf.id}",
            program_id=cf.program_id,
            decision="deleted",
            reason=f"{cf.vuln_type}@{cf.host}",
            actor=actor,
        )
    )
    db.delete(cf)
    db.commit()
    return Response(status_code=204)
