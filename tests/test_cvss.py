"""اختبارات حاسبة CVSS v3.1 وآلة الحالات — جزء من Phase 7."""

from api.services.cvss import auto_cvss, base_score, severity_from_score
from api.services.triage import can_transition, is_valid_status


def test_known_cvss_vectors():
    # قيم مرجعية معروفة من مواصفة CVSS 3.1
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert base_score("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1  # XSS انعكاسي كلاسيكي
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_severity_bands():
    assert severity_from_score(0.0) == "info"
    assert severity_from_score(3.9) == "low"
    assert severity_from_score(6.9) == "medium"
    assert severity_from_score(8.9) == "high"
    assert severity_from_score(9.8) == "critical"


def test_auto_cvss_by_type():
    score, vector = auto_cvss("sqli", "high")
    assert vector.startswith("CVSS:3.1/")
    assert score >= 7.0  # SQLi خطورة عالية

    score_rce, _ = auto_cvss("rce", "critical")
    assert score_rce == 9.8


def test_transitions():
    assert can_transition("needs_review", "confirmed") is True
    assert can_transition("confirmed", "reported") is True
    assert can_transition("needs_review", "resolved") is False  # لا قفز
    assert can_transition("confirmed", "resolved") is False
    assert can_transition("reported", "resolved") is True
    assert can_transition("resolved", "confirmed") is False     # نهائية


def test_status_validation():
    assert is_valid_status("confirmed") is True
    assert is_valid_status("banana") is False
