"""بناء تعليمة Strix من الحسابات المُنشأة (بدون كشف أي سر في السجلّات).

تُمرَّر كلمات المرور لـ Strix (الذي يشغّل الاستغلال في sandbox) فقط عند التشغيل،
ولا تُطبَع ولا تُعاد عبر الـ API.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from api.models.account import ProvisionedAccount
from api.services.crypto import get_cipher


def strix_idor_instruction(db: Session, program_id: int) -> str | None:
    """تعليمة تطلب من Strix اختبار IDOR بالحسابين المُنشأين (تتضمّن الاعتمادات)."""
    cipher = get_cipher()
    if cipher is None:
        return None
    rows = (
        db.query(ProvisionedAccount)
        .filter_by(program_id=program_id, status="created")
        .order_by(ProvisionedAccount.label)
        .all()
    )
    creds = []
    for row in rows:
        if not row.secret_encrypted:
            continue
        creds.append({"label": row.label, "username": row.identifier,
                      "password": cipher.decrypt(row.secret_encrypted)})
    if len(creds) < 2:
        return None
    return (
        "Test for IDOR and broken access control using these two test accounts. "
        "Log in as account A, capture object references (IDs, document/order/profile URLs) "
        "that belong only to A, then attempt to read or modify them while authenticated as "
        "account B. Report any cross-account access as IDOR. Accounts: " + json.dumps(creds)
    )
