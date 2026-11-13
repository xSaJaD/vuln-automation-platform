"""لقطة سطح الهجوم للفحص التفاضلي (asset_snapshots)."""

from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin


class AssetSnapshot(Base, TimestampMixin):
    __tablename__ = "asset_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(Text)   # عناصر البصمة، سطر لكل عنصر
    item_count: Mapped[int] = mapped_column(Integer, default=0)
