"""سجل التدقيق (audit_log) — كل قرار نطاق يُسجَّل هنا. لا مسار يتجاوزه."""

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(50))          # scope_check ...
    target_value: Mapped[str] = mapped_column(String(500))
    program_id: Mapped[int | None] = mapped_column(ForeignKey("programs.id"), nullable=True)
    decision: Mapped[str] = mapped_column(String(20))        # allow | deny
    reason: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(100), default="system")
