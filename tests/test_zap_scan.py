"""اختبارات دمج ZAP — تحويل التنبيهات + فرض النطاق + تمرير الكوكي (بعميل وهمي)."""

from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.scan import Finding
from workers.zap_scan import alert_to_finding, run_zap_scan


def test_alert_to_finding_maps_risk_and_fields():
    f = alert_to_finding(
        1,
        {
            "alert": "SQL Injection",
            "risk": "High",
            "url": "http://dvwa/vulnerabilities/sqli/?id=1",
            "param": "id",
            "evidence": "SQL syntax",
            "cweid": "89",
        },
    )
    assert f.severity == "high"
    assert f.vuln_type == "SQL Injection"
    assert f.host == "dvwa"
    assert f.source_tool == "zap"
    assert "param=id" in f.evidence and "CWE-89" in f.evidence


def test_alert_risk_informational_maps_info():
    f = alert_to_finding(1, {"alert": "X", "risk": "Informational", "url": "http://dvwa/"})
    assert f.severity == "info"


# ── عميل ZAP وهمي: spider/ascan "منتهية"، ويُرجِع تنبيهات ثابتة ──
class _FakeZap:
    def __init__(self, alerts):
        self._alerts = alerts
        self.calls = []

    def request(self, path, params=None):
        self.calls.append((path, params or {}))
        if path.endswith("/action/scan/"):
            return {"scan": "0"}
        if path.endswith("/view/status/"):
            return {"status": "100"}        # منتهية فورًا — لا انتظار فعلي
        if path.endswith("/view/alerts/"):
            return {"alerts": self._alerts}
        return {}


def _program(db):
    p = Program(name="DVWA", handle="dvwa")
    p.scope_assets = [ScopeAsset(kind=AssetKind.domain, identifier="dvwa", in_scope=True)]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def test_run_zap_scan_stores_and_enforces_scope(db_session):
    p = _program(db_session)
    zap = _FakeZap(
        [
            {"alert": "Command Injection", "risk": "High",
             "url": "http://dvwa/vulnerabilities/exec/", "param": "ip"},
            {"alert": "External leak", "risk": "Medium", "url": "http://evil.com/x"},  # خارج النطاق
        ]
    )
    scan_run, findings = run_zap_scan(db_session, p, "http://dvwa/", zap, cookie_header="PHPSESSID=s; security=low")

    # تنبيه evil.com حُجب؛ فقط dvwa خُزّن.
    assert len(findings) == 1
    assert findings[0].vuln_type == "Command Injection"
    blocks = db_session.query(AuditLog).filter_by(action="zap_scope_block").all()
    assert len(blocks) == 1
    assert db_session.query(Finding).filter_by(source_tool="zap").count() == 1

    # مُرّر الكوكي عبر قاعدة Replacer.
    assert any(c[0].endswith("/replacer/action/addRule/") for c in zap.calls)


def test_run_zap_scan_no_cookie_skips_replacer(db_session):
    p = _program(db_session)
    zap = _FakeZap([])
    run_zap_scan(db_session, p, "http://dvwa/", zap, cookie_header="")
    assert not any(c[0].endswith("/replacer/action/addRule/") for c in zap.calls)


# ── نقطة الـ API ──
def test_zapscan_api_rejects_out_of_scope(client):
    pid = client.post("/programs", json={"name": "DVWA", "handle": "dvwa"}).json()["id"]
    client.post(f"/programs/{pid}/scope", json={"kind": "domain", "identifier": "dvwa", "in_scope": True})
    r = client.post(f"/programs/{pid}/zapscan", json={"seed": "http://evil.com/"})
    assert r.status_code == 403
