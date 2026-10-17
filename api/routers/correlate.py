"""تشغيل الدمج وعرض الـ findings الموحّدة."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api import schemas
from api.db import get_db
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
