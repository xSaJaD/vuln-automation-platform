"""متابعة حالة مهام Celery — حتى تتابع اللوحة تقدّم الفحص بدون تيرمنال.

يُعيد حالة المهمة (PENDING/STARTED/SUCCESS/FAILURE) وملخّصًا آمنًا للنتيجة فقط.
لا يكشف تتبّع الاستثناءات (تبقى في سجلّات الـ worker).
"""

from fastapi import APIRouter

router = APIRouter(tags=["tasks"])


@router.get("/tasks/{task_id}")
def task_status(task_id: str):
    """حالة مهمة واحدة. عند تعذّر الوصول للـ backend نُعيد PENDING بأمان
    (تستمرّ اللوحة بالاستطلاع حتى المهلة بدل أن تفشل)."""
    try:
        from workers.celery_app import celery_app

        res = celery_app.AsyncResult(task_id)
        state = res.state
        ready = res.ready()
    except Exception:
        return {"task_id": task_id, "state": "PENDING", "ready": False}

    out: dict = {"task_id": task_id, "state": state, "ready": ready}
    try:
        if res.successful():
            result = res.result
            # dict كما هو (ملخّص المهمة)؛ أي نوع آخر يُحوّل لنصّ.
            out["result"] = result if isinstance(result, dict) else {"value": str(result)}
        elif res.failed():
            out["error"] = "فشلت المهمة — راجع سجلّات الـ worker"
    except Exception:
        pass
    return out
