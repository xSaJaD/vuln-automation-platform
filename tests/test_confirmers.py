"""اختبارات محرّك التأكيد النشط (بعميل HTTP وهمي) + تطبيقه على النتائج."""

from api.models.program import AssetKind, Program, ScopeAsset
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.schemas import CorrelatedFindingOut
from workers.confirm_logic import run_confirmations
from workers.confirmers import (
    Verdict,
    confirm_cors,
    confirm_finding,
    confirm_open_redirect,
    confirm_sqli,
    confirm_xss,
    pick_confirmer,
)


class _Resp:
    def __init__(self, text="", headers=None, status=200, elapsed=0.1):
        self.text = text
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.status = status
        self.elapsed = elapsed


class _Probe:
    """عميل وهمي — يستدعي handler(url, headers) لصياغة الرد."""

    def __init__(self, handler):
        self.handler = handler

    def get(self, url, headers=None, allow_redirects=True):
        return self.handler(url, headers or {})


def test_sqli_confirmed_by_db_error():
    # inject() يرمّز ' إلى %27 في الرابط (السلوك الصحيح على السلك).
    def h(url, headers):
        return _Resp("You have an error in your SQL syntax near ...") if "%27" in url else _Resp("ok")
    assert confirm_sqli(_Probe(h), "http://h/x?id=1", "id").status == "confirmed"


def test_sqli_time_based_confirmed():
    def h(url, headers):
        return _Resp("ok", elapsed=5.2) if "SLEEP" in url else _Resp("ok", elapsed=0.1)
    assert confirm_sqli(_Probe(h), "http://h/x?id=1", "id").status == "confirmed"


def test_sqli_unconfirmed():
    assert confirm_sqli(_Probe(lambda u, hh: _Resp("normal page")), "http://h/x?id=1", "id").status == "unconfirmed"


def test_xss_confirmed_on_reflection():
    def h(url, headers):
        return _Resp("<html><svg/onload=confirm(IQ9173)></html>")
    assert confirm_xss(_Probe(h), "http://h/x?q=1", "q").status == "confirmed"


def test_xss_unconfirmed_when_encoded():
    def h(url, headers):
        return _Resp("&lt;svg/onload=...&gt;")   # مُرمَّز => غير مؤكّد
    assert confirm_xss(_Probe(h), "http://h/x?q=1", "q").status == "unconfirmed"


def test_open_redirect_confirmed_via_location():
    def h(url, headers):
        return _Resp("", headers={"Location": "https://iq9173-evil.example/"}, status=302)
    assert confirm_open_redirect(_Probe(h), "http://h/r?url=1", "url").status == "confirmed"


def test_cors_confirmed_reflects_origin():
    def h(url, headers):
        return _Resp("", headers={"Access-Control-Allow-Origin": "https://iq9173-evil.example",
                                  "Access-Control-Allow-Credentials": "true"})
    assert confirm_cors(_Probe(h), "http://h/api", None).status == "confirmed"


def test_ssrf_is_manual():
    assert pick_confirmer("SSRF") is not None
    v = confirm_finding(_Probe(lambda u, hh: _Resp("")), "SSRF", "h", "http://h/x", None)
    assert v.status == "manual"


def test_unknown_type_no_confirmer():
    assert confirm_finding(_Probe(lambda u, hh: _Resp("")), "Some Weird Thing", "h", "http://h/x", None).status == "manual"


# ── التكامل: run_confirmations يحدّث الحالة والثقة ──
def _program_with_finding(db, vuln_type, endpoint):
    p = Program(name="D", handle="d")
    p.scope_assets = [ScopeAsset(kind=AssetKind.domain, identifier="h", in_scope=True)]
    db.add(p)
    db.commit()
    db.refresh(p)
    sr = ScanRun(program_id=p.id, run_name="n", tool="nuclei", status=ScanStatus.done)
    db.add(sr)
    db.commit()
    db.refresh(sr)
    db.add(Finding(scan_run_id=sr.id, host="h", endpoint=endpoint, vuln_type=vuln_type,
                   severity="high", source_tool="nuclei", status=FindingStatus.needs_review,
                   evidence="param=id"))
    db.commit()
    from workers.correlation_logic import correlate
    return p, correlate(db, p)[0]


def test_run_confirmations_confirms_and_boosts_confidence(db_session):
    p, cf = _program_with_finding(db_session, "SQL Injection", "http://h/x?id=1")

    def h(url, headers):
        return _Resp("SQL syntax error") if "%27" in url else _Resp("ok")

    counts = run_confirmations(db_session, p, _Probe(h))
    assert counts["confirmed"] == 1
    db_session.refresh(cf)
    assert cf.status == FindingStatus.confirmed
    assert cf.evidence.startswith("✔")
    # الثقة ترتفع إلى 98 عبر الحقل المحسوب.
    out = CorrelatedFindingOut.model_validate(cf)
    assert out.confidence == 98


def test_run_confirmations_marks_false_positive_low_confidence(db_session):
    p, cf = _program_with_finding(db_session, "SQL Injection", "http://h/x?id=1")
    counts = run_confirmations(db_session, p, _Probe(lambda u, hh: _Resp("normal")))
    assert counts["unconfirmed"] == 1
    db_session.refresh(cf)
    assert cf.status == FindingStatus.needs_review       # لا يُأكَّد تلقائيًا
    assert cf.evidence.startswith("✖")
    out = CorrelatedFindingOut.model_validate(cf)
    assert out.confidence == 15                          # ثقة منخفضة = غالبًا كاذب


def test_verdict_dataclass():
    assert Verdict("confirmed", "x").status == "confirmed"
