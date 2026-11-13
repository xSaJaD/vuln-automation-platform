"""تخزين الـ endpoints المكتشفة من JS على المضيفات (تدخل الفحص عبر Host.urls).

nuclei يفحص كل رابط في Host.urls؛ لذا تخزين الـ endpoints هنا يعني أنها ستُفحَص
في التشغيل التالي. كل endpoint ضمن النطاق فقط، ويُسجَّل العدد في audit_log.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.program import Program
from api.models.recon import Host
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import evaluate, host_of


def store_endpoints(
    db: Session, program: Program, endpoints: list[str], actor: str = "js-discovery"
) -> dict:
    """يدمج الـ endpoints في Host.urls (حسب المضيف)، منشئًا مضيفًا عند اللزوم."""
    rules = rules_for(program)
    by_host: dict[str, list[str]] = {}
    dropped = 0
    for ep in endpoints:
        if not evaluate(ep, rules).allowed:     # حارس النطاق — دفاع إضافي
            dropped += 1
            continue
        by_host.setdefault(host_of(ep), []).append(ep)

    added = 0
    for hostname, urls in by_host.items():
        host = (
            db.query(Host).filter_by(program_id=program.id, hostname=hostname).first()
            or Host(program_id=program.id, hostname=hostname, source="js-discovery",
                    in_scope=True, is_live=True)
        )
        if host.id is None:
            db.add(host)
        existing = [u for u in (host.urls or "").splitlines() if u.strip()]
        merged = list(dict.fromkeys(existing + urls))
        added += len(merged) - len(existing)
        host.urls = "\n".join(merged)
        host.in_scope = True

    db.add(AuditLog(action="js_endpoints_stored", target_value=str(len(endpoints)),
                    program_id=program.id, decision="allow",
                    reason=f"{added} endpoint جديد على {len(by_host)} مضيف "
                           f"({dropped} خارج النطاق أُهمِل)", actor=actor))
    db.commit()
    return {"discovered": len(endpoints), "stored": added, "hosts": len(by_host), "dropped": dropped}
