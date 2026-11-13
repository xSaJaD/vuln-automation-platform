"""ملف مصادقة دائم لكل برنامج (auth_profiles).

يُخزَّن مرة واحدة ويُستخدم تلقائيًا في كل فحص مُصادَق — تسجيل دخول نموذجي عام
يصلح لأي موقع. كلمة المرور **مشفّرة** (Fernet) ولا تُعاد أبدًا عبر الـ API.
"""

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin


class AuthProfile(Base, TimestampMixin):
    __tablename__ = "auth_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    # ملف واحد لكل برنامج (unique) — "دائمًا يسجّل الدخول" بهذا الملف.
    program_id: Mapped[int] = mapped_column(
        ForeignKey("programs.id", ondelete="CASCADE"), unique=True
    )
    login_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    username: Mapped[str | None] = mapped_column(String(300), nullable=True)
    password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    username_field: Mapped[str] = mapped_column(String(100), default="username")
    password_field: Mapped[str] = mapped_column(String(100), default="password")
    token_field: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # قواميس JSON كنصّ: {"Login":"Login"} و {"security":"low"}.
    extra_fields: Mapped[str] = mapped_column(Text, default="{}")
    extra_cookies: Mapped[str] = mapped_column(Text, default="{}")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
