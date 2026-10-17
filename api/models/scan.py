"""عمليات الفحص ونتائجها (scan_runs, findings)."""

import enum

from sqlalchemy import Boolean, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.models.base import Base, TimestampMixin


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    done = "done"
    failed = "failed"


class FindingStatus(str, enum.Enum):
    needs_review = "needs_review"
    confirmed = "confirmed"
    reported = "reported"
    resolved = "resolved"
    duplicate = "duplicate"
    not_applicable = "not_applicable"


class ScanRun(Base, TimestampMixin):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    run_name: Mapped[str] = mapped_column(String(200))
    tool: Mapped[str] = mapped_column(String(50))  # nuclei | strix | recon ...
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.queued)


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id", ondelete="CASCADE"))
    host: Mapped[str] = mapped_column(String(300))
    endpoint: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    vuln_type: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(20), default="info")
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_tool: Mapped[str] = mapped_column(String(50))
    confirmed_by_strix: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.needs_review)
