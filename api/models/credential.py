"""اعتمادات grey-box المخزَّنة مُشفّرة (credentials).

الحقل secret_encrypted يحوي قيمة مُشفّرة فقط — لا يُخزَّن سر بنص صريح أبدًا،
ولا تُعاد القيمة عبر الـ API.
"""

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin


class Credential(Base, TimestampMixin):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"))
    label: Mapped[str] = mapped_column(String(100))
    secret_encrypted: Mapped[str] = mapped_column(Text)
