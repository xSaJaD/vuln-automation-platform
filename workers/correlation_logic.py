"""منطق التوحيد والدمج (Normalize + Correlate) — نقي وقابل للاختبار.

يجمع الـ findings الخام (من nuclei و Strix) حسب (host + endpoint + نوع الثغرة)،
ويُنتج finding موحّد واحد لكل مجموعة:
  • sources = كل الأدوات التي رصدته.
  • confirmed_by_strix = True لو أي مصدر هو Strix أو مؤكَّد منه.
  • severity = أعلى خطورة بين المصادر.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from api.models.correlation import CorrelatedFinding
from api.models.program import Program
from api.models.scan import Finding, ScanRun

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def correlation_key(host: str | None, endpoint: str | None, vuln_type: str | None) -> str:
    return "|".join(
        [
            (host or "").strip().lower(),
            (endpoint or "").strip().lower(),
            (vuln_type or "").strip().lower(),
        ]
    )


def _max_severity(severities: list[str]) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s.lower(), 0), default="info")


def correlate(db: Session, program: Program) -> list[CorrelatedFinding]:
    raw = (
        db.query(Finding)
        .join(ScanRun, Finding.scan_run_id == ScanRun.id)
        .filter(ScanRun.program_id == program.id)
        .all()
    )

    groups: dict[str, list[Finding]] = {}
    for finding in raw:
        key = correlation_key(finding.host, finding.endpoint, finding.vuln_type)
        groups.setdefault(key, []).append(finding)

    results: list[CorrelatedFinding] = []
    for key, items in groups.items():
        sources = sorted({i.source_tool for i in items})
        confirmed = any(i.confirmed_by_strix or i.source_tool == "strix" for i in items)
        severity = _max_severity([i.severity for i in items])
        evidence = next((i.evidence for i in items if i.evidence), None)

        cf = (
            db.query(CorrelatedFinding)
            .filter_by(program_id=program.id, correlation_key=key)
            .first()
        )
        if cf is None:
            cf = CorrelatedFinding(program_id=program.id, correlation_key=key)
            db.add(cf)

        cf.host = items[0].host
        cf.endpoint = items[0].endpoint
        cf.vuln_type = items[0].vuln_type
        cf.severity = severity
        cf.sources = ",".join(sources)
        cf.confirmed_by_strix = confirmed
        cf.evidence = evidence
        cf.finding_count = len(items)
        results.append(cf)

    db.commit()
    return results
