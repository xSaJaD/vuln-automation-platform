"""تطبيق المؤكِّدات على النتائج المخزّنة وتحديث حالتها/ثقتها — نقّي وقابل للاختبار.

لكل نتيجة needs_review ضمن النطاق: يشغّل المؤكِّد المناسب، ويضع علامة بالدليل:
  ✔ مؤكّد نشط  → status=confirmed (ثقة عالية)
  ✖ لم يُؤكَّد   → يبقى needs_review (ثقة منخفضة — غالبًا إيجابي كاذب)
  ؟ يدوي       → يحتاج تحقّقًا بشريًا
"""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.correlation import CorrelatedFinding
from api.models.program import Program
from api.models.scan import FindingStatus
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import evaluate
from workers.confirmers import confirm_finding

_MARKER = re.compile(r"^[✔✖؟] [^|]*\|\s?")


def _strip_marker(ev: str | None) -> str:
    return _MARKER.sub("", ev or "")


def run_confirmations(db: Session, program: Program, probe, actor: str = "confirm") -> dict:
    rules = rules_for(program)
    cfs = db.query(CorrelatedFinding).filter_by(program_id=program.id).all()
    counts = {"confirmed": 0, "unconfirmed": 0, "manual": 0, "error": 0, "skipped": 0}

    for cf in cfs:
        # نؤكّد فقط ما لم يُراجَع بعد، وضمن النطاق.
        if cf.status != FindingStatus.needs_review or not evaluate(cf.host, rules).allowed:
            counts["skipped"] += 1
            continue

        v = confirm_finding(probe, cf.vuln_type, cf.host, cf.endpoint, cf.evidence)
        clean = _strip_marker(cf.evidence)
        tail = f" | {clean}" if clean else ""

        if v.status == "confirmed":
            cf.status = FindingStatus.confirmed
            cf.evidence = f"✔ مؤكّد نشط: {v.signal}{tail}"
            counts["confirmed"] += 1
        elif v.status == "unconfirmed":
            cf.evidence = f"✖ لم يُؤكَّد: {v.signal}{tail}"
            counts["unconfirmed"] += 1
        elif v.status == "manual":
            cf.evidence = f"؟ يدوي: {v.signal}{tail}"
            counts["manual"] += 1
        else:
            counts["error"] += 1

    db.add(
        AuditLog(
            action="confirm_run",
            target_value=f"program:{program.id}",
            program_id=program.id,
            decision="done",
            reason=f"confirmed={counts['confirmed']} unconfirmed={counts['unconfirmed']}",
            actor=actor,
        )
    )
    db.commit()
    return counts
