"""الحسابات المُنشأة تلقائيًا على الهدف (provisioned_accounts) — لاختبار IDOR.

اختبار IDOR / وصول غير مصرّح يتطلب حسابين مستقلين (A و B): ننشئ حساب A، نكتشف
مرجع كائن يملكه (رابط لبياناته)، ثم نحاول الوصول إليه بجلسة B. لو نجح B => IDOR.

- كلمة المرور وبيانات الجلسة (cookies/token) تُخزَّن **مشفّرة فقط** (Fernet).
- لا يُعاد أي سر عبر الـ API — فقط بيانات وصفية.
- كل إنشاء حساب يمرّ عبر Scope Gatekeeper ويُسجَّل في audit_log.
"""

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin


class ProvisionedAccount(Base, TimestampMixin):
    __tablename__ = "provisioned_accounts"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"))
    label: Mapped[str] = mapped_column(String(50))          # "idor-a" / "idor-b"
    identifier: Mapped[str] = mapped_column(String(200))    # البريد/اسم المستخدم (غير سرّي)
    register_host: Mapped[str] = mapped_column(String(300)) # المضيف الذي أُنشئ عليه (للتدقيق)
    status: Mapped[str] = mapped_column(String(20), default="created")  # created | failed
    # أسرار — مشفّرة دائمًا، لا تُعاد عبر الـ API أبدًا.
    secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)   # كلمة المرور
    session_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON: cookies/token
