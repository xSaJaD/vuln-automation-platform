"""تحميل ملف المصادقة المخزَّن (فكّ تشفير كلمة المرور) — وحدة نقية بلا FastAPI.

مهمّة: لا تستورد أي Router هنا. العامل (worker) يستورد هذه الوحدة، وحاوية العامل
فيها تعارض نسخ FastAPI/Starlette (بسبب strix-agent)، فاستيراد أي APIRouter داخلها
يفشل. لذلك يبقى هذا المنطق منفصلًا عن طبقة الراوترات.
"""

from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.models.auth_profile import AuthProfile
from api.services.crypto import get_cipher


def load_login_config(db: Session, program_id: int) -> dict | None:
    """يحمّل ملف المصادقة النشط ويفكّ تشفير كلمة المرور.

    يرجّع dict متوافقًا مع LoginConfig، أو None إن لم يوجد ملف نشط.
    """
    profile = db.scalar(select(AuthProfile).where(AuthProfile.program_id == program_id))
    if profile is None or not profile.active:
        return None
    password = None
    if profile.password_encrypted:
        cipher = get_cipher()
        if cipher is not None:
            try:
                password = cipher.decrypt(profile.password_encrypted)
            except Exception:
                password = None
    return {
        "url": profile.login_url,
        "username": profile.username,
        "password": password,
        "username_field": profile.username_field,
        "password_field": profile.password_field,
        "token_field": profile.token_field,
        "extra_fields": json.loads(profile.extra_fields or "{}"),
        "extra_cookies": json.loads(profile.extra_cookies or "{}"),
    }
