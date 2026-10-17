"""أساس المهام المرن: إعادة محاولة مع backoff + تسجيل في dead-letter عند الفشل النهائي."""

from __future__ import annotations

from celery import Task

# سياسة إعادة المحاولة المشتركة للمهام الثقيلة.
RETRY = {
    "autoretry_for": (Exception,),
    "retry_backoff": True,       # 2s, 4s, 8s ...
    "retry_backoff_max": 600,
    "retry_jitter": True,
    "max_retries": 3,
}


class ResilientTask(Task):
    """يُسجّل المهمة في failed_tasks بعد استنفاد كل المحاولات."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        from api.db import SessionLocal
        from api.services.resilience import record_failed_task

        db = SessionLocal()
        try:
            record_failed_task(db, self.name or "?", list(args), f"{type(exc).__name__}: {exc}")
        except Exception:
            pass  # لا نُفشل معالج الفشل نفسه
        finally:
            db.close()
