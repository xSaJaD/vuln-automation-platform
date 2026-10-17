"""تطبيق Celery — طابور المهام للـ recon والفحص."""

from celery import Celery
from celery.schedules import crontab

from api.config import settings

_broker = settings.redis_url or "redis://localhost:6379/0"

celery_app = Celery("strix", broker=_broker, backend=_broker)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_time_limit=1800,  # حد أقصى لوقت تنفيذ المهمة
)

# جدولة دورية (Celery beat): recon كامل أسبوعيًا لكل برنامج نشط.
# قفل التزامن في pipeline.run_full يمنع أي تداخل بين التشغيلات.
celery_app.conf.beat_schedule = {
    "weekly-recon": {
        "task": "pipeline.scheduled_recon",
        "schedule": crontab(day_of_week=1, hour=3, minute=0),  # كل اثنين 03:00
    },
    "monitor-workers": {
        "task": "monitor.check_workers",
        "schedule": 300.0,  # كل 5 دقائق — تنبيه إن انقطع العمّال
    },
}

# سجلّات JSON منظّمة للعمّال.
from api.config import settings as _settings  # noqa: E402
from api.logging_config import setup_logging as _setup_logging  # noqa: E402

if _settings.log_json:
    _setup_logging(_settings.log_level)

# استيراد المهام حتى تُسجَّل مع التطبيق.
import workers.tasks  # noqa: E402,F401
