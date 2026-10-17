"""طابور الرسائل الميتة (dead-letter) — مهام فشلت نهائيًا بعد كل المحاولات."""

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin


class FailedTask(Base, TimestampMixin):
    __tablename__ = "failed_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_name: Mapped[str] = mapped_column(String(100))
    args: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str] = mapped_column(Text)
