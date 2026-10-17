"""CRUD للبرامج ونطاقها + قراءة سجل التدقيق الخاص بالبرنامج."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api import schemas
from api.db import get_db
from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset

router = APIRouter(prefix="/programs", tags=["programs"])


@router.post("", response_model=schemas.ProgramOut, status_code=201)
def create_program(payload: schemas.ProgramIn, db: Session = Depends(get_db)):
    if db.scalar(select(Program).where(Program.handle == payload.handle)):
        raise HTTPException(409, f"handle موجود مسبقًا: {payload.handle}")
    prog = Program(**payload.model_dump())
    db.add(prog)
    db.commit()
    db.refresh(prog)
    return prog


@router.get("", response_model=list[schemas.ProgramOut])
def list_programs(db: Session = Depends(get_db)):
    return list(db.scalars(select(Program)))


@router.get("/{program_id}", response_model=schemas.ProgramOut)
def get_program(program_id: int, db: Session = Depends(get_db)):
    prog = db.get(Program, program_id)
    if not prog:
        raise HTTPException(404, "البرنامج غير موجود")
    return prog


@router.post("/{program_id}/scope", response_model=schemas.ScopeAssetOut, status_code=201)
def add_scope_asset(program_id: int, payload: schemas.ScopeAssetIn, db: Session = Depends(get_db)):
    prog = db.get(Program, program_id)
    if not prog:
        raise HTTPException(404, "البرنامج غير موجود")
    try:
        kind = AssetKind(payload.kind)
    except ValueError:
        valid = ", ".join(k.value for k in AssetKind)
        raise HTTPException(422, f"نوع asset غير صالح: {payload.kind} (المسموح: {valid})")

    asset = ScopeAsset(
        program_id=program_id,
        kind=kind,
        identifier=payload.identifier,
        in_scope=payload.in_scope,
        max_severity=payload.max_severity,
        notes=payload.notes,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{program_id}/scope", response_model=list[schemas.ScopeAssetOut])
def list_scope_assets(program_id: int, db: Session = Depends(get_db)):
    prog = db.get(Program, program_id)
    if not prog:
        raise HTTPException(404, "البرنامج غير موجود")
    return prog.scope_assets


@router.get("/{program_id}/audit")
def list_audit(program_id: int, db: Session = Depends(get_db)):
    rows = db.scalars(
        select(AuditLog).where(AuditLog.program_id == program_id).order_by(AuditLog.id.desc())
    )
    return [
        {
            "id": r.id,
            "action": r.action,
            "target_value": r.target_value,
            "decision": r.decision,
            "reason": r.reason,
            "actor": r.actor,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
