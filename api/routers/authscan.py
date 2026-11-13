"""فحص مُصادَق (Authenticated DAST) — تسجيل دخول ثم nuclei -dast بلا Strix.

كل هدف يمر عبر Scope Gatekeeper قبل جدولة أي مهمة.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db import get_db
from api.models.program import AssetKind, Program
from api.services.scope_gatekeeper import check_target
from api.services.scope_matching import host_of

router = APIRouter(tags=["authscan"])


class LoginIn(BaseModel):
    url: str | None = None
    username: str | None = None
    password: str | None = None
    username_field: str = "username"
    password_field: str = "password"
    token_field: str | None = None
    extra_fields: dict[str, str] = {}
    extra_cookies: dict[str, str] = {}


class AuthScanIn(BaseModel):
    # فارغة => تُشتقّ الأهداف من أصول النطاق من نوع url المخزّنة.
    targets: list[str] = []
    # None => يستخدم العامل ملف المصادقة المخزَّن للبرنامج (تسجيل دخول دائم).
    login: LoginIn | None = None


def _url_scope_targets(program: Program) -> list[str]:
    """روابط من نوع url ضمن النطاق — أهداف الفحص المُصادَق الدائمة."""
    return [
        a.identifier
        for a in program.scope_assets
        if a.in_scope and a.active and a.kind == AssetKind.url
    ]


@router.post("/programs/{program_id}/authscan")
def trigger_authscan(program_id: int, payload: AuthScanIn, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")

    targets = payload.targets or _url_scope_targets(program)
    if not targets:
        raise HTTPException(
            422,
            "لا أهداف — أضف روابط (نوع url) للنطاق أو مرّر targets صراحة.",
        )

    # فرض النطاق على مضيف كل هدف قبل أي شيء (يُسجَّل في audit_log).
    for tgt in targets:
        host = host_of(tgt) or tgt
        decision = check_target(db, program, host, actor="authscan-trigger")
        if not decision.allowed:
            raise HTTPException(403, f"هدف خارج النطاق: {tgt} ({decision.reason})")

    login = payload.login.model_dump() if payload.login else None
    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("authscan.run", args=[program_id, targets, login])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")

    return {"status": "queued", "task_id": task.id, "targets": len(targets)}


class AutoScanIn(BaseModel):
    seed: str  # رابط بداية فقط — النظام يسجّل دخول ويزحف ويفحص بنفسه


@router.post("/programs/{program_id}/autoscan")
def trigger_autoscan(program_id: int, payload: AutoScanIn, db: Session = Depends(get_db)):
    """فحص ذاتي: دخول تلقائي + زحف + fuzzing — بإدخال رابط بداية واحد فقط."""
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")

    host = host_of(payload.seed) or payload.seed
    decision = check_target(db, program, host, actor="autoscan-trigger")
    if not decision.allowed:
        raise HTTPException(403, f"البذرة خارج النطاق: {payload.seed} ({decision.reason})")

    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("autoscan.run", args=[program_id, payload.seed])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")

    return {"status": "queued", "task_id": task.id, "seed": payload.seed}


class ZapScanIn(BaseModel):
    seed: str  # رابط بداية — ZAP يزحف ويفحص نشطًا (مُصادَقًا) انطلاقًا منه


@router.post("/programs/{program_id}/zapscan")
def trigger_zapscan(program_id: int, payload: ZapScanIn, db: Session = Depends(get_db)):
    """فحص عميق عبر OWASP ZAP (spider + active scan مُصادَق)."""
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")

    host = host_of(payload.seed) or payload.seed
    decision = check_target(db, program, host, actor="zap-trigger")
    if not decision.allowed:
        raise HTTPException(403, f"البذرة خارج النطاق: {payload.seed} ({decision.reason})")

    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("zap.run", args=[program_id, payload.seed])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")

    return {"status": "queued", "task_id": task.id, "seed": payload.seed}
