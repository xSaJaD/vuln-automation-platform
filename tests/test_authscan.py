"""اختبارات الفحص المُصادَق (Authenticated DAST) — تسجيل دخول + فرض النطاق."""

from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.scan import Finding
from workers.authscan import (
    LoginConfig,
    authenticate,
    cookie_header,
    extract_token,
    run_authscan,
)


# ── عميل HTTP وهمي لاختبار منطق تسجيل الدخول بلا شبكة ──
class _FakeResp:
    def __init__(self, text):
        self.text = text


class _FakeClient:
    def __init__(self, page_html, jar):
        self._page = page_html
        self._jar = jar
        self.posted = None

    def get(self, url):
        return _FakeResp(self._page)

    def post(self, url, data):
        self.posted = data
        return _FakeResp("ok")

    def cookies(self):
        return self._jar


def test_extract_token_scrapes_hidden_field():
    html = '<form><input type="hidden" name="user_token" value="abc123"></form>'
    assert extract_token(html, "user_token") == "abc123"
    assert extract_token(html, "missing") is None


def test_authenticate_scrapes_token_and_merges_cookies():
    html = '<input name="user_token" value="tok42">'
    client = _FakeClient(html, {"PHPSESSID": "sess1"})
    cfg = LoginConfig(
        url="http://dvwa/login.php",
        username="admin",
        password="password",
        token_field="user_token",
        extra_fields={"Login": "Login"},
        extra_cookies={"security": "low"},
    )
    cookies = authenticate(client, cfg)

    # الـ token كُشط ومُرّر مع بيانات الدخول.
    assert client.posted["user_token"] == "tok42"
    assert client.posted["username"] == "admin"
    assert client.posted["Login"] == "Login"
    # كوكي الجلسة + security=low.
    assert cookies["PHPSESSID"] == "sess1"
    assert cookies["security"] == "low"


def test_cookie_header_format():
    assert cookie_header({"PHPSESSID": "x", "security": "low"}) == "PHPSESSID=x; security=low"


def _program_with_scope(db):
    p = Program(name="DVWA", handle="dvwa")
    p.scope_assets = [ScopeAsset(kind=AssetKind.domain, identifier="dvwa", in_scope=True)]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def test_run_authscan_enforces_scope_and_stores_findings(db_session):
    p = _program_with_scope(db_session)
    targets = [
        "http://dvwa/vulnerabilities/xss_r/?name=x",   # ضمن النطاق
        "http://evil.com/?q=1",                          # خارج النطاق — يُحجب
    ]

    seen = {}

    def fake_dast(tgts):
        seen["targets"] = list(tgts)
        return [
            {
                "template-id": "dast/vulnerabilities/xss/reflected-xss",
                "info": {"name": "Reflected XSS", "severity": "high"},
                "host": "dvwa",
                "matched-at": "http://dvwa/vulnerabilities/xss_r/?name=x",
                "fuzzing-parameter": "name",
            }
        ]

    scan_run, findings = run_authscan(db_session, p, targets, fake_dast)

    # الهدف خارج النطاق لم يُمرَّر إلى nuclei إطلاقًا.
    assert seen["targets"] == ["http://dvwa/vulnerabilities/xss_r/?name=x"]
    # حُجب evil.com وسُجّل في audit_log.
    blocks = db_session.query(AuditLog).filter_by(action="authscan_scope_block").all()
    assert len(blocks) == 1
    # النتيجة خُزّنت كـ nuclei-dast بحالة needs_review.
    assert len(findings) == 1
    assert findings[0].source_tool == "nuclei-dast"
    assert findings[0].vuln_type.endswith("reflected-xss")
    stored = db_session.query(Finding).filter_by(source_tool="nuclei-dast").all()
    assert len(stored) == 1


def test_run_authscan_no_safe_targets_is_empty(db_session):
    p = _program_with_scope(db_session)

    def fake_dast(tgts):  # لا يجب أن تُستدعى
        raise AssertionError("يجب ألا يُستدعى nuclei بلا أهداف ضمن النطاق")

    scan_run, findings = run_authscan(db_session, p, ["http://evil.com/?q=1"], fake_dast)
    assert findings == []


# ── اختبارات نقطة الـ API ──
def _api_program(client):
    pid = client.post("/programs", json={"name": "DVWA", "handle": "dvwa"}).json()["id"]
    client.post(
        f"/programs/{pid}/scope",
        json={"kind": "domain", "identifier": "dvwa", "in_scope": True},
    )
    return pid


def test_authscan_api_rejects_out_of_scope(client):
    pid = _api_program(client)
    r = client.post(
        f"/programs/{pid}/authscan",
        json={"targets": ["http://evil.com/?q=1"]},
    )
    assert r.status_code == 403


def test_authscan_api_requires_targets(client):
    pid = _api_program(client)
    r = client.post(f"/programs/{pid}/authscan", json={"targets": []})
    assert r.status_code == 422
