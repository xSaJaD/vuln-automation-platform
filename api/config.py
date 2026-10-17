"""إعدادات التطبيق — تُقرأ من متغيرات البيئة فقط (لا أسرار في الكود)."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    log_level: str = "info"
    api_port: int = 8000

    # تُستخدم فعليًا من المراحل اللاحقة؛ تبقى اختيارية في Phase 0.
    db_url: str = ""
    redis_url: str = ""
    strix_llm: str = ""

    # مجلد حفظ النتائج الخام (JSONL) — يُركّب كـ volume في الـ worker.
    strix_runs_dir: str = "strix_runs"
    # مجلد حفظ مسودّات التقارير.
    reports_out_dir: str = "reports/out"

    # دمج Strix
    llm_api_key: str = ""
    strix_budget: str = ""   # حد أقصى لتكلفة LLM لكل تشغيل (اختياري)
    strix_timeout: int = 1800

    # الأمان
    field_encryption_key: str = ""     # Fernet key لتشفير الحقول الحساسة
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 300   # لكل IP على الـ API

    # التنبيهات والمراقبة
    notify_webhook_url: str = ""        # Slack/Telegram/عام
    notify_min_severity: str = "high"   # أدنى خطورة تُنبِّه
    log_json: bool = True

    # HackerOne API (مزامنة النطاق)
    hackerone_api_username: str = ""
    hackerone_api_token: str = ""


settings = Settings()
