"""مفاتيح API وأدوارها (RBAC). يُخزَّن هاش المفتاح فقط، لا المفتاح الخام."""

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin


class ApiKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(20), default="viewer")  # admin | viewer
    label: Mapped[str | None] = mapped_column(String(100), nullable=True)
