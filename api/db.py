"""إعداد محرك قاعدة البيانات والجلسات.

- في الإنتاج/Docker: PostgreSQL عبر DB_URL.
- محليًا بدون إعداد: يسقط تلقائيًا على ملف SQLite للتجربة.
المخطط الرسمي يُدار عبر Alembic؛ init_db() وسيلة راحة للتطوير فقط.
"""

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from api.config import settings
from api.models.base import Base

_DB_URL = settings.db_url or "sqlite:///./dev.db"
_connect_args = {"check_same_thread": False} if _DB_URL.startswith("sqlite") else {}

engine = create_engine(_DB_URL, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """ينشئ الجداول إن لم تكن موجودة (تطوير فقط — الإنتاج يستخدم Alembic)."""
    import api.models  # noqa: F401  يضمن تحميل كل النماذج

    Base.metadata.create_all(bind=engine)
