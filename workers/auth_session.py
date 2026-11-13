"""بناء ترويسات المصادقة من جلسة حساب مُنشأ — لفحص nuclei/المعاملات مصادَقًا."""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from api.models.account import ProvisionedAccount
from api.services.crypto import get_cipher


def auth_headers_for(db: Session, program_id: int, label: str = "idor-a") -> dict[str, str]:
    """يرجّع {Cookie/Authorization} لجلسة حساب مُنشأ، أو {} إن تعذّر."""
    cipher = get_cipher()
    if cipher is None:
        return {}
    q = db.query(ProvisionedAccount).filter_by(program_id=program_id, status="created")
    row = q.filter_by(label=label).first() or q.order_by(ProvisionedAccount.label).first()
    if not row or not row.session_encrypted:
        return {}
    data = json.loads(cipher.decrypt(row.session_encrypted))
    headers: dict[str, str] = {}
    cookies = data.get("cookies") or {}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    if data.get("token"):
        headers["Authorization"] = data["token"]
    return headers
