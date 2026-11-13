"""اختبارات مولّد PoC ودرجة الثقة (التطابق المتقاطع)."""

from api.schemas import CorrelatedFindingOut
from api.services.poc import build_poc


def test_poc_sqli_has_curl_and_sqlmap():
    poc = build_poc("SQL Injection", "dvwa", "http://dvwa/vulnerabilities/sqli/?id=1", "param=id")
    assert "curl" in poc
    assert "sqlmap" in poc            # مؤكِّد مستهدف للـ SQLi
    assert "id=" in poc


def test_poc_xss_injects_payload():
    poc = build_poc("Reflected XSS", "dvwa", "http://dvwa/vulnerabilities/xss_r/?name=x", "param=name")
    assert "curl" in poc
    assert "<script>" in poc
    assert "name=" in poc


def test_poc_command_injection_has_post_variant():
    poc = build_poc("Remote OS Command Injection", "dvwa", "http://dvwa/vulnerabilities/exec/", "param=ip")
    assert "curl" in poc
    assert "POST" in poc              # نماذج الحقن غالبًا POST


def test_poc_uses_evidence_payload():
    poc = build_poc("SQLi", "h", "http://h/x?id=1", "param=id; attack=1 AND SLEEP(5)")
    assert "SLEEP(5)" in poc          # يستخدم الحمولة الحقيقية من الدليل


def _cf(**over):
    base = dict(
        id=1, program_id=1, host="dvwa", endpoint="http://dvwa/x", vuln_type="SQL Injection",
        severity="high", sources="nuclei", confirmed_by_strix=False, evidence=None,
        finding_count=1, status="needs_review", cvss_score=9.8, cvss_vector=None,
        cvss_manual=False, likely_duplicate=False, duplicate_ref=None, submitted_ref=None,
    )
    base.update(over)
    return CorrelatedFindingOut.model_validate(base)


def test_confidence_single_source_low():
    assert _cf(sources="nuclei").confidence == 45


def test_confidence_rises_with_corroboration_and_strix():
    # مصدران + تأكيد Strix + دليل => ثقة عالية.
    o = _cf(sources="nuclei,zap", confirmed_by_strix=True, evidence="param=id")
    assert o.confidence >= 90
    # الحقل poc يُولَّد تلقائيًا ضمن المخرجات.
    assert "curl" in o.poc


def test_confidence_three_sources():
    assert _cf(sources="nuclei,zap,strix").confidence >= 90
