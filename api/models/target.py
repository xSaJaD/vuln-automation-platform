"""الأهداف (targets) — كل هدف يمر عبر Scope Gatekeeper قبل أي فحص."""

import enum

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin


class TargetStatus(str, enum.Enum):
    pending = "pending"    # لم يُقيَّم بعد
    approved = "approved"  # ضمن النطاق — مسموح بالفحص
    rejected = "rejected"  # خارج النطاق — مرفوض، لا يُفحص أبدًا


class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"))
    value: Mapped[str] = mapped_column(String(500))
    status: Mapped[TargetStatus] = mapped_column(Enum(TargetStatus), default=TargetStatus.pending)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
