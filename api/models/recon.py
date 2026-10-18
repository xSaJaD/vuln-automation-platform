"""مضيفات الـ recon المكتشفة (hosts).

كل مضيف يُقيَّم بـ Scope Gatekeeper؛ in_scope=False يُسجَّل لكن لا يُفحص أبدًا.
"""

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin


class Host(Base, TimestampMixin):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("program_id", "hostname", name="uq_host_program"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"))
    hostname: Mapped[str] = mapped_column(String(300))
    ip: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_live: Mapped[bool] = mapped_column(Boolean, default=False)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(String(300), nullable=True)
    tech: Mapped[str | None] = mapped_column(Text, nullable=True)       # قائمة مفصولة بفواصل
    open_ports: Mapped[str | None] = mapped_column(String(200), nullable=True)
    source: Mapped[str] = mapped_column(String(50), default="subfinder")
    # نتيجة Scope Gatekeeper — المضيفات خارج النطاق لا تُفحص إطلاقًا.
    in_scope: Mapped[bool] = mapped_column(Boolean, default=False)
    # كشف الحظر: "blocked" أو "clean" (Phase 17).
    block_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
