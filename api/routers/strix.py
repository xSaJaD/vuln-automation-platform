"""تشغيل محرك Strix (الذكاء الاصطناعي) على هدف ضمن النطاق.

وضعان:
  • /strix          — فحص جديد من الصفر (مع prompt اختياري).
  • /strix/continue — يحقن نتائج الفحص السابق (بلا LLM) كسياق، فيتحقّق منها Strix
                      ويكمل من تلك النقطة بدل إعادة البدء.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.config import settings
from api.db import get_db
from api.models.correlation import CorrelatedFinding
from api.models.program import Program
from api.services.scope_gatekeeper import check_target

router = APIRouter(tags=["strix"])


class StrixIn(BaseModel):
    target: str                      # رابط ويب / repo / OpenAPI spec ضمن النطاق
    instruction: str | None = None   # تعليمات/prompt اختيارية


def _require_llm() -> None:
    if not (settings.llm_api_key or "").strip():
        raise HTTPException(
            400,
            "Strix يحتاج مفتاح LLM — عيّن LLM_API_KEY (و STRIX_LLM) في .env ثم أعد تشغيل الـ worker.",
        )


def _enqueue(program_id: int, target: str, instruction: str | None) -> dict:
    try:
        from workers.celery_app import celery_app

        task = celery_app.send_task("strix.run", args=[program_id, target, instruction])
    except Exception as exc:
        raise HTTPException(503, f"طابور المهام غير متاح: {exc}")
    return {"status": "queued", "task_id": task.id, "target": target}


@router.post("/programs/{program_id}/strix")
def trigger_strix(program_id: int, payload: StrixIn, db: Session = Depends(get_db)):
    """فحص Strix جديد من الصفر."""
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")
    _require_llm()
    decision = check_target(db, program, payload.target, actor="strix-trigger")
    if not decision.allowed:
        raise HTTPException(403, f"الهدف خارج النطاق — لا يبدأ Strix: {decision.reason}")
    return _enqueue(program_id, payload.target, payload.instruction)


@router.post("/programs/{program_id}/strix/continue")
def trigger_strix_continue(program_id: int, payload: StrixIn, db: Session = Depends(get_db)):
    """يحقن النتائج السابقة كسياق ليتحقّق منها Strix ويكمل من حيث توقّفنا."""
    program = db.get(Program, program_id)
    if not program:
        raise HTTPException(404, "البرنامج غير موجود")
    _require_llm()
    decision = check_target(db, program, payload.target, actor="strix-continue")
    if not decision.allowed:
        raise HTTPException(403, f"الهدف خارج النطاق — لا يبدأ Strix: {decision.reason}")

    prior = list(
        db.scalars(
            select(CorrelatedFinding)
            .where(CorrelatedFinding.program_id == program_id)
            .order_by(CorrelatedFinding.id.desc())
        )
    )
    lines = [
        f"- {c.vuln_type} @ {c.host}{(' ' + c.endpoint) if c.endpoint else ''} "
        f"(severity={c.severity}, sources={c.sources})"
        for c in prior[:50]
    ]
    if lines:
        context = (
            "اكتشف فحص آليّ سابق (بلا تحقّق ذكاء اصطناعي) النتائج التالية — بعضها قد يكون "
            "إيجابيًا كاذبًا. تحقّق أيّها حقيقي عبر الاستغلال الفعلي، وأكمل الفحص من هذه "
            "النقطة بدل إعادة البدء من الصفر:\n" + "\n".join(lines)
        )
    else:
        context = "لا نتائج سابقة مخزّنة — ابدأ فحصًا كاملًا للهدف."

    instruction = ((payload.instruction + "\n\n") if payload.instruction else "") + context
    return _enqueue(program_id, payload.target, instruction)
