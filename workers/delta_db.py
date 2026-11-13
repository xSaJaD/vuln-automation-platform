"""الفحص التفاضلي على مستوى قاعدة البيانات: يحفظ لقطة ويقارنها بالسابقة."""

from __future__ import annotations

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.program import Program
from api.models.recon import Host
from api.models.snapshot import AssetSnapshot
from workers.delta import diff, fingerprint_hosts


def snapshot_and_diff(db: Session, program: Program, actor: str = "delta") -> dict:
    """يحسب بصمة سطح الهجوم الحالي، يقارنها بآخر لقطة، ثم يحفظ الحالية."""
    hosts = db.query(Host).filter_by(program_id=program.id).all()
    current = fingerprint_hosts(hosts)

    prev_row = (
        db.query(AssetSnapshot)
        .filter_by(program_id=program.id)
        .order_by(AssetSnapshot.id.desc())
        .first()
    )
    previous = set((prev_row.fingerprint or "").splitlines()) if prev_row else set()
    result = diff(previous, current)

    db.add(AssetSnapshot(program_id=program.id, fingerprint="\n".join(sorted(current)),
                         item_count=len(current)))
    db.add(AuditLog(action="delta_snapshot", target_value=str(len(result["added"])),
                    program_id=program.id, decision="allow",
                    reason=f"{len(result['new_urls'])} رابط جديد، {len(result['new_hosts'])} مضيف جديد",
                    actor=actor))
    db.commit()
    result["first_run"] = prev_row is None
    return result
