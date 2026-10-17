"""الـ findings الموحّدة بعد الدمج (correlated_findings).

finding واحد لكل (host + endpoint + نوع الثغرة)، يجمع كل المصادر التي رصدته.
"""

from sqlalchemy import Boolean, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin
from api.models.scan import FindingStatus


class CorrelatedFinding(Base, TimestampMixin):
    __tablename__ = "correlated_findings"
    __table_args__ = (
        UniqueConstraint("program_id", "correlation_key", name="uq_correlated_key"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"))
    correlation_key: Mapped[str] = mapped_column(String(600))
    host: Mapped[str] = mapped_column(String(300))
    endpoint: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    vuln_type: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20), default="info")
    sources: Mapped[str] = mapped_column(String(100))  # "nuclei,strix"
    confirmed_by_strix: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.needs_review)

    # CVSS (Phase 7) — تلقائي ما لم يُعدّله الباحث يدويًا.
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cvss_manual: Mapped[bool] = mapped_column(Boolean, default=False)
