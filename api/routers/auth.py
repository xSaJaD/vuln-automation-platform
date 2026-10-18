"""إدارة مفاتيح API (RBAC). المفتاح الخام يُعرَض مرة واحدة فقط."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db import get_db
from api.models.api_key import ApiKey
from api.services.auth import generate_api_key, hash_key

router = APIRouter(tags=["auth"])


class ApiKeyIn(BaseModel):
    role: str = "viewer"
    label: str | None = None


@router.post("/auth/keys", status_code=201)
def create_key(payload: ApiKeyIn, db: Session = Depends(get_db)):
    if payload.role not in ("admin", "viewer"):
        raise HTTPException(422, "الدور يجب أن يكون admin أو viewer")
    raw = generate_api_key()
    key = ApiKey(key_hash=hash_key(raw), role=payload.role, label=payload.label)
    db.add(key)
    db.commit()
    db.refresh(key)
    # المفتاح الخام يُعرَض مرة واحدة فقط — لا يُخزَّن ولا يُعاد لاحقًا.
    return {"id": key.id, "role": key.role, "label": key.label, "api_key": raw}


@router.get("/auth/keys")
def list_keys(db: Session = Depends(get_db)):
    rows = db.scalars(select(ApiKey))
    return [
        {"id": k.id, "role": k.role, "label": k.label, "created_at": k.created_at.isoformat()}
        for k in rows
    ]
