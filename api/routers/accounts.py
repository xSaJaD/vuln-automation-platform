"""إنشاء حسابات اختبار (لـ IDOR) وتشغيل الفحص التفاضلي.

كل العمليات كتابية => تتطلب دور admin حين تفعيل RBAC. مضيف التسجيل/الموارد يمرّ
عبر Scope Gatekeeper، وإنشاء الحسابات يتطلب إقرار ROE (allow_account_provisioning).
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db import get_db
from api.models.account import ProvisionedAccount
from api.models.program import Program
from api.services.scope_gatekeeper import check_target
from workers.account_logic import DEFAULT_ACCOUNTS, MAX_ACCOUNTS

router = APIRouter(tags=["accounts"])


class RecipeIn(BaseModel):
    register_url: str
    method: str = "POST"
    content_type: str = "form"
    fields: dict[str, str] = Field(default_factory=dict)
    email_field: str = "email"
    password_field: str = "password"
    username_field: str | None = None
    success_status: list[int] = Field(default_factory=lambda: [200, 201, 302])
    success_marker: str | None = None
    login_url: str | None = None
    login_fields: dict[str, str] = Field(default_factory=dict)


class ProvisionIn(BaseModel):
    recipe: RecipeIn
    count: int = DEFAULT_ACCOUNTS


class AutoProvisionIn(BaseModel):
    seed: str                 # نطاق/رابط ضمن النطاق — يُزحف لاكتشاف نموذج التسجيل
    count: int = DEFAULT_ACCOUNTS


class AutoIdorIn(BaseModel):
    seed_urls: list[str]      # صفحات مصادَقة للحساب A تُزحف لاستخراج مراجع الكائنات


class ResourceIn(BaseModel):
    url: str
    owner_label: str          # الحساب المالك، مثل "idor-a"
    marker: str               # نص يميّز بيانات المالك داخل الرد


class IdorIn(BaseModel):
    resources: list[ResourceIn]


@router.post("/programs/{program_id}/accounts/provision")
def provision(program_id: int, payload: ProvisionIn, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")
    if not program.allow_account_provisioning:
        raise HTTPException(
            403, "إنشاء الحسابات غير مُفعَّل — فعّل allow_account_provisioning (إقرار ROE) أولًا"
        )
    if not program.account_email_domain:
        raise HTTPException(422, "عيّن account_email_domain (نطاق بريد يملكه الباحث) أولًا")
    if payload.count > MAX_ACCOUNTS:
        raise HTTPException(422, f"الحدّ الأقصى {MAX_ACCOUNTS} حسابات (هذا لاختبار IDOR لا لإغراق الموقع)")

    decision = check_target(db, program, payload.recipe.register_url, actor="provision-trigger")
    if not decision.allowed:
        raise HTTPException(403, f"مضيف التسجيل خارج النطاق: {decision.reason}")

    recipe = payload.recipe.model_dump()
    recipe["success_status"] = tuple(recipe["success_status"])
    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("accounts.provision", args=[program_id, recipe, payload.count])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")
    return {"status": "queued", "task_id": task.id}


@router.post("/programs/{program_id}/accounts/auto-provision")
def auto_provision(program_id: int, payload: AutoProvisionIn, db: Session = Depends(get_db)):
    """يكتشف نموذج التسجيل بالزحف ثم ينشئ الحسابات (نفس حواجز /provision)."""
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")
    if not program.allow_account_provisioning:
        raise HTTPException(403, "إنشاء الحسابات غير مُفعَّل — فعّل allow_account_provisioning (ROE)")
    if not program.account_email_domain:
        raise HTTPException(422, "عيّن account_email_domain (نطاق بريد يملكه الباحث) أولًا")
    if payload.count > MAX_ACCOUNTS:
        raise HTTPException(422, f"الحدّ الأقصى {MAX_ACCOUNTS} حسابات")

    decision = check_target(db, program, payload.seed, actor="auto-provision-trigger")
    if not decision.allowed:
        raise HTTPException(403, f"البذرة خارج النطاق: {decision.reason}")

    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task(
            "accounts.discover_provision", args=[program_id, payload.seed, payload.count])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")
    return {"status": "queued", "task_id": task.id}


@router.post("/programs/{program_id}/idor/auto")
def auto_idor(program_id: int, payload: AutoIdorIn, db: Session = Depends(get_db)):
    """يكتشف مراجع كائنات الحساب A بالزحف ثم يفحص IDOR (يتطلب حسابين مُنشأين)."""
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")
    if not payload.seed_urls:
        raise HTTPException(422, "لزوم صفحة بذرة واحدة على الأقل")
    for url in payload.seed_urls:
        decision = check_target(db, program, url, actor="idor-auto-trigger")
        if not decision.allowed:
            raise HTTPException(403, f"البذرة خارج النطاق ({url}): {decision.reason}")

    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("idor.auto", args=[program_id, payload.seed_urls])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")
    return {"status": "queued", "task_id": task.id}


@router.get("/programs/{program_id}/accounts")
def list_accounts(program_id: int, db: Session = Depends(get_db)):
    if not db.get(Program, program_id):
        raise HTTPException(404, "البرنامج غير موجود")
    rows = db.scalars(
        select(ProvisionedAccount).where(ProvisionedAccount.program_id == program_id)
    )
    # لا أسرار في المخرجات — بيانات وصفية فقط.
    return [
        {"id": a.id, "label": a.label, "identifier": a.identifier,
         "register_host": a.register_host, "status": a.status,
         "created_at": a.created_at.isoformat()}
        for a in rows
    ]


@router.post("/programs/{program_id}/idor")
def run_idor_scan(program_id: int, payload: IdorIn, db: Session = Depends(get_db)):
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")
    if not payload.resources:
        raise HTTPException(422, "لزوم مورد واحد على الأقل (url + owner_label + marker)")

    # كل مورد يمرّ عبر الحارس قبل الجدولة — لا طلب على رابط خارج النطاق.
    for r in payload.resources:
        decision = check_target(db, program, r.url, actor="idor-trigger")
        if not decision.allowed:
            raise HTTPException(403, f"المورد خارج النطاق ({r.url}): {decision.reason}")

    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task(
            "idor.run", args=[program_id, [r.model_dump() for r in payload.resources]]
        )
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")
    return {"status": "queued", "task_id": task.id}
