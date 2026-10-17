"""تجميع كل النماذج حتى تُعبّأ Base.metadata (مهم لـ Alembic autogenerate)."""

from api.models.audit import AuditLog
from api.models.base import Base
from api.models.correlation import CorrelatedFinding
from api.models.credential import Credential
from api.models.failed_task import FailedTask
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.recon import Host
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.models.target import Target, TargetStatus

__all__ = [
    "Base",
    "Program",
    "ScopeAsset",
    "AssetKind",
    "Target",
    "TargetStatus",
    "Host",
    "ScanRun",
    "Finding",
    "ScanStatus",
    "FindingStatus",
    "CorrelatedFinding",
    "Credential",
    "FailedTask",
    "AuditLog",
]
