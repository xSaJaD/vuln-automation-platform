"""فحص التكرار — مقارنة النتائج بتقارير سابقة (منطق نقي قابل للاختبار).

finding يُعدّ تكرارًا محتملًا إذا طابق الأصل (host) نفسه ونوع الثغرة تقريرًا سابقًا.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from api.models.correlation import CorrelatedFinding


def _norm(s) -> str:
    return (s or "").strip().lower()


def is_duplicate(finding, priors):
    """يرجّع التقرير المطابق (PriorReport) أو None."""
    fhost = _norm(_get(finding, "host"))
    ftype = _norm(_get(finding, "vuln_type"))
    if not fhost:
        return None
    for p in priors:
        asset = _norm(p.asset)
        host_match = bool(asset) and (asset == fhost or fhost.endswith("." + asset) or asset in fhost)
        type_match = bool(ftype) and ftype.split()[0] in _norm(p.title)
        if host_match and type_match:
            return p
    return None


def _get(obj, name):
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def flag_duplicates(db: Session, program, priors) -> int:
    """يعلّم النتائج المطابقة بـ likely_duplicate=True. يرجّع عددها."""
    rows = db.query(CorrelatedFinding).filter_by(program_id=program.id).all()
    flagged = 0
    for cf in rows:
        if cf.likely_duplicate:
            continue
        match = is_duplicate(cf, priors)
        if match:
            cf.likely_duplicate = True
            cf.duplicate_ref = f"{match.source}: {match.title}"[:500]
            flagged += 1
    db.commit()
    return flagged
