"""تسجيل المهام الفاشلة نهائيًا (dead-letter). دالة نقية بلا اعتماد على Celery."""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from api.models.failed_task import FailedTask


def record_failed_task(db: Session, task_name: str, args, error: str) -> FailedTask:
    ft = FailedTask(
        task_name=task_name,
        args=json.dumps(args, ensure_ascii=False, default=str)[:2000],
        error=(error or "")[:2000],
    )
    db.add(ft)
    db.commit()
    db.refresh(ft)
    return ft
