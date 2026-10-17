"""تخزين اعتمادات grey-box مُشفّرة. السر لا يُعاد أبدًا عبر الـ API."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db import get_db
from api.models.audit import AuditLog
from api.models.credential import Credential
from api.models.program import Program
from api.services.crypto import get_cipher

router = APIRouter(tags=["credentials"])


class CredentialIn(BaseModel):
    label: str
    secret: str


@router.post("/programs/{program_id}/credentials", status_code=201)
def add_credential(program_id: int, payload: CredentialIn, db: Session = Depends(get_db)):
    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")

    cipher = get_cipher()
    if cipher is None:
        raise HTTPException(
            503, "التشفير غير مُهيّأ — عيّن FIELD_ENCRYPTION_KEY قبل تخزين أي سر."
        )

    cred = Credential(
        program_id=program_id,
        label=payload.label,
        secret_encrypted=cipher.encrypt(payload.secret),
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)

    db.add(
        AuditLog(
            action="credential_add",
            target_value=payload.label,
            program_id=program_id,
            decision="stored",
            reason="encrypted",
            actor="api",
        )
    )
    db.commit()
    # السر لا يُعاد.
    return {"id": cred.id, "label": cred.label}


@router.get("/programs/{program_id}/credentials")
def list_credentials(program_id: int, db: Session = Depends(get_db)):
    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")
    rows = db.scalars(select(Credential).where(Credential.program_id == program_id))
    # لا سر في المخرجات — بيانات وصفية فقط.
    return [{"id": c.id, "label": c.label, "created_at": c.created_at.isoformat()} for c in rows]
