"""البرامج ونطاقها (programs, scope_assets)."""

import enum

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.models.base import Base, TimestampMixin


class AssetKind(str, enum.Enum):
    domain = "domain"      # نطاق دقيق:      example.com
    wildcard = "wildcard"  # wildcard:        *.example.com (النطاقات الفرعية فقط)
    ip = "ip"              # عنوان IP:        203.0.113.10
    cidr = "cidr"          # شبكة:            203.0.113.0/24
    url = "url"            # رابط محدد:       https://app.example.com
    repo = "repo"          # مستودع:          github.com/org/repo


class Program(Base, TimestampMixin):
    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    handle: Mapped[str] = mapped_column(String(100), unique=True)
    platform: Mapped[str] = mapped_column(String(50), default="hackerone")
    policy_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # قواعد الاشتباك (Rules of Engagement)
    roe_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    rate_limit_per_min: Mapped[int | None] = mapped_column(Integer, nullable=True)

    scope_assets: Mapped[list["ScopeAsset"]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )


class ScopeAsset(Base, TimestampMixin):
    __tablename__ = "scope_assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"))
    kind: Mapped[AssetKind] = mapped_column(Enum(AssetKind))
    identifier: Mapped[str] = mapped_column(String(300))
    # in_scope=False يعني أنه مُستبعَد صراحة (out-of-scope) — ويتغلّب دائمًا.
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    max_severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    instruction: Mapped[str | None] = mapped_column(Text, nullable=True)
    # يُعطَّل تلقائيًا عند خروج الأصل من نطاق البرنامج (Scope Sync).
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    program: Mapped["Program"] = relationship(back_populates="scope_assets")
