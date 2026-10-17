"""إنشاء هدف — يمر إجباريًا عبر Scope Gatekeeper قبل أن يُقبل."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api import schemas
from api.db import get_db
from api.models.program import Program
from api.models.target import Target, TargetStatus
from api.services.scope_gatekeeper import check_target

router = APIRouter(prefix="/targets", tags=["targets"])


@router.post("", response_model=schemas.TargetOut, status_code=201)
def create_target(payload: schemas.TargetIn, db: Session = Depends(get_db)):
    prog = db.get(Program, payload.program_id)
    if not prog:
        raise HTTPException(404, "البرنامج غير موجود")

    # لا يُقبل أي هدف دون المرور من هنا. القرار يُسجَّل في audit_log.
    decision = check_target(db, prog, payload.value, actor="api")
    status = TargetStatus.approved if decision.allowed else TargetStatus.rejected

    target = Target(
        program_id=prog.id,
        value=payload.value,
        status=status,
        decision_reason=decision.reason,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("", response_model=list[schemas.TargetOut])
def list_targets(db: Session = Depends(get_db)):
    return list(db.scalars(select(Target)))
