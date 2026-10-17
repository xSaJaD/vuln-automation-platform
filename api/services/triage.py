"""آلة حالات الـ finding (triage state machine).

needs_review → confirmed / not_applicable / duplicate
confirmed     → reported / not_applicable / duplicate / needs_review
reported      → resolved / duplicate
resolved / duplicate / not_applicable: نهائية (مع رجوع محدود للتصحيح)
"""

from api.models.scan import FindingStatus

_TRANSITIONS: dict[str, set[str]] = {
    "needs_review": {"confirmed", "not_applicable", "duplicate"},
    "confirmed": {"reported", "not_applicable", "duplicate", "needs_review"},
    "reported": {"resolved", "duplicate"},
    "resolved": set(),
    "duplicate": set(),
    "not_applicable": {"needs_review"},
}


def can_transition(current: str, new: str) -> bool:
    if current == new:
        return True
    return new in _TRANSITIONS.get(current, set())


def is_valid_status(value: str) -> bool:
    return value in {s.value for s in FindingStatus}
