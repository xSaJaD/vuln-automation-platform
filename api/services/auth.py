"""RBAC عبر API keys. الحارس اختياري (AUTH_ENABLED).

عند التفعيل: كل الطلبات تتطلب مفتاحًا صالحًا؛ عمليات الكتابة تتطلب دور admin.
استثناء bootstrap: يُسمح بإنشاء أول مفتاح حين لا توجد مفاتيح بعد.
"""

from __future__ import annotations

import hashlib
import secrets

from fastapi import Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.config import settings
from api.db import get_db
from api.models.api_key import ApiKey

PUBLIC_PATHS = {"/", "/dashboard", "/health", "/health/workers"}
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def generate_api_key() -> str:
    return "iqs_" + secrets.token_urlsafe(32)


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def verify_key(db: Session, raw: str) -> ApiKey | None:
    if not raw:
        return None
    return db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_key(raw)))


def count_keys(db: Session) -> int:
    return db.scalar(select(func.count(ApiKey.id))) or 0


def auth_guard(request: Request, db: Session = Depends(get_db)) -> None:
    if not settings.auth_enabled:
        return
    path = request.url.path
    if path in PUBLIC_PATHS:
        return

    key = verify_key(db, request.headers.get("X-API-Key", ""))
    if key is None:
        # bootstrap: السماح بإنشاء أول مفتاح حين لا توجد مفاتيح.
        if path == "/auth/keys" and request.method == "POST" and count_keys(db) == 0:
            return
        raise HTTPException(401, "مفتاح API مطلوب (X-API-Key)")

    if request.method in _WRITE_METHODS and key.role != "admin":
        raise HTTPException(403, "صلاحية admin مطلوبة لهذه العملية")
