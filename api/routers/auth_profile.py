"""ملف مصادقة دائم لكل برنامج — يُحفظ مرة ويُستخدم في كل فحص مُصادَق.

كلمة المرور تُخزَّن مشفّرة (Fernet) ولا تُعاد أبدًا عبر الـ API.
"""

import json

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db import get_db
from api.models.audit import AuditLog
from api.models.auth_profile import AuthProfile
from api.models.program import Program
from api.services.crypto import get_cipher

router = APIRouter(tags=["auth-profile"])


class AuthProfileIn(BaseModel):
    login_url: str | None = None
    username: str | None = None
    password: str | None = None            # يُخزَّن مشفّرًا؛ فارغ عند التحديث = إبقاء القديم
    username_field: str = "username"
    password_field: str = "password"
    token_field: str | None = None
    extra_fields: dict[str, str] = {}
    extra_cookies: dict[str, str] = {}
    active: bool = True


def _out(p: AuthProfile) -> dict:
    """تمثيل آمن — بلا كلمة مرور، مع has_password فقط."""
    return {
        "program_id": p.program_id,
        "login_url": p.login_url,
        "username": p.username,
        "has_password": bool(p.password_encrypted),
        "username_field": p.username_field,
        "password_field": p.password_field,
        "token_field": p.token_field,
        "extra_fields": json.loads(p.extra_fields or "{}"),
        "extra_cookies": json.loads(p.extra_cookies or "{}"),
        "active": p.active,
    }


@router.put("/programs/{program_id}/auth")
def upsert_auth(program_id: int, payload: AuthProfileIn, db: Session = Depends(get_db)):
    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")

    profile = db.scalar(select(AuthProfile).where(AuthProfile.program_id == program_id))
    if profile is None:
        profile = AuthProfile(program_id=program_id)
        db.add(profile)

    profile.login_url = payload.login_url
    profile.username = payload.username
    profile.username_field = payload.username_field
    profile.password_field = payload.password_field
    profile.token_field = payload.token_field
    profile.extra_fields = json.dumps(payload.extra_fields, ensure_ascii=False)
    profile.extra_cookies = json.dumps(payload.extra_cookies, ensure_ascii=False)
    profile.active = payload.active

    # كلمة المرور: تُشفَّر عند تقديمها؛ إن تُركت فارغة يبقى المخزَّن كما هو.
    if payload.password:
        cipher = get_cipher()
        if cipher is None:
            raise HTTPException(
                503, "التشفير غير مُهيّأ — عيّن FIELD_ENCRYPTION_KEY قبل تخزين كلمة المرور."
            )
        profile.password_encrypted = cipher.encrypt(payload.password)

    db.add(
        AuditLog(
            action="auth_profile_set",
            target_value=payload.login_url or "login",
            program_id=program_id,
            decision="stored",
            reason="encrypted" if profile.password_encrypted else "no-password",
            actor="dashboard",
        )
    )
    db.commit()
    db.refresh(profile)
    return _out(profile)


@router.get("/programs/{program_id}/auth")
def get_auth(program_id: int, db: Session = Depends(get_db)):
    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")
    profile = db.scalar(select(AuthProfile).where(AuthProfile.program_id == program_id))
    if profile is None:
        return {"configured": False}
    return {"configured": True, **_out(profile)}


@router.delete("/programs/{program_id}/auth", status_code=204)
def delete_auth(program_id: int, db: Session = Depends(get_db)):
    profile = db.scalar(select(AuthProfile).where(AuthProfile.program_id == program_id))
    if profile is None:
        raise HTTPException(404, "لا ملف مصادقة لهذا البرنامج")
    db.delete(profile)
    db.commit()
    return Response(status_code=204)


# ملاحظة: منطق تحميل الملف للعامل يعيش في api/services/auth_loader.py
# (وحدة نقية بلا FastAPI) — لا تستورده من هنا داخل الـ worker.
