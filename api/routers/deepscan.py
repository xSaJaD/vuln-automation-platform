"""فحوصات عميقة: مصادَق، معاملات، تحكّم وصول، تفاضلي، وقياس الدقّة."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db import get_db
from api.models.correlation import CorrelatedFinding
from api.models.program import Program
from api.services.benchmark import finding_key, score

router = APIRouter(tags=["deepscan"])


def _queue(name, args):
    from workers.celery_app import celery_app
    try:
        return celery_app.send_task(name, args=args)
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")


def _require(db, program_id):
    p = db.get(Program, program_id)
    if not p:
        raise HTTPException(404, "البرنامج غير موجود")
    return p


class AuthScanIn(BaseModel):
    dast: bool = True
    label: str = "idor-a"


@router.post("/programs/{program_id}/scan/authenticated")
def authenticated_scan(program_id: int, payload: AuthScanIn, db: Session = Depends(get_db)):
    """nuclei مصادَق بجلسة الحساب + فحص معاملات على مضيفات النطاق."""
    _require(db, program_id)
    task = _queue("scan.authenticated", [program_id, payload.dast, payload.label])
    return {"status": "queued", "task_id": task.id}


@router.post("/programs/{program_id}/fuzz")
def fuzz(program_id: int, db: Session = Depends(get_db)):
    """فحص معاملات متحقَّق (XSS/SQLi/redirect/traversal) + معاملات مخفية."""
    _require(db, program_id)
    task = _queue("params.fuzz", [program_id])
    return {"status": "queued", "task_id": task.id}


@router.post("/programs/{program_id}/access-check")
def access_check(program_id: int, db: Session = Depends(get_db)):
    """تصعيد صلاحيات رأسي: مسارات إدارية بجلسة مستخدم عادي."""
    _require(db, program_id)
    task = _queue("access.check", [program_id])
    return {"status": "queued", "task_id": task.id}


@router.post("/programs/{program_id}/delta")
def delta(program_id: int, db: Session = Depends(get_db)):
    """فحص تفاضلي: يرصد الجديد في سطح الهجوم منذ آخر لقطة."""
    _require(db, program_id)
    task = _queue("scan.delta", [program_id])
    return {"status": "queued", "task_id": task.id}


class ExpectedVuln(BaseModel):
    vuln_class: str
    host: str | None = None
    endpoint: str | None = None


class BenchmarkIn(BaseModel):
    expected: list[ExpectedVuln] = Field(default_factory=list)


@router.post("/programs/{program_id}/benchmark")
def benchmark(program_id: int, payload: BenchmarkIn, db: Session = Depends(get_db)):
    """يقيس precision/recall/F1 لنتائج البرنامج مقابل قائمة ثغرات معروفة (ground truth)."""
    _require(db, program_id)
    rows = db.scalars(select(CorrelatedFinding).where(CorrelatedFinding.program_id == program_id))
    found = {finding_key(c.vuln_class, c.host, c.endpoint) for c in rows}
    expected = {finding_key(e.vuln_class, e.host, e.endpoint) for e in payload.expected}
    result = score(found, expected)
    return result.__dict__
