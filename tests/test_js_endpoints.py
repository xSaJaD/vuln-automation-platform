"""اختبارات: استخراج الـ endpoints من JS، جمعها من الصفحة، تخزينها، والسلسلة المصادَقة."""

import pytest

from api.config import settings
from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.recon import Host
from api.services.crypto import generate_key
from api.services.html_forms import parse_page
from api.services.scope_matching import ScopeRule
from workers.account_logic import RegisterResult
from workers.endpoints_db import store_endpoints
from workers.js_discovery import Fetched, discover_js_endpoints
from workers.js_endpoints import extract_endpoints

_RULES = [ScopeRule(kind="wildcard", identifier="*.example.com", in_scope=True),
          ScopeRule(kind="domain", identifier="example.com", in_scope=True)]


# ── استخراج الـ endpoints من JS ──

def test_extract_paths_and_calls():
    js = '''
      const API = "/api/v1";
      fetch("/api/v1/users");
      axios.get("/orders/42");
      xhr.open("GET", "/admin/settings");
      var full = "https://app.example.com/profile/me";
      var img = "/logo.png"; var mime = "application/json";
    '''
    eps = extract_endpoints(js, "https://app.example.com/main.js")
    assert "https://app.example.com/api/v1/users" in eps
    assert "https://app.example.com/orders/42" in eps
    assert "https://app.example.com/admin/settings" in eps
    assert "https://app.example.com/profile/me" in eps
    assert not any("logo.png" in e for e in eps)          # صورة مُهمَلة
    assert not any("json" in e.split("/")[-1] for e in eps if "application" in e)


def test_extract_ignores_third_party_host():
    js = 'fetch("https://evil.com/steal"); fetch("/local/api")'
    eps = extract_endpoints(js, "https://app.example.com/a.js")
    assert eps == ["https://app.example.com/local/api"]    # الطرف الثالث مُهمَل


def test_extract_without_base_returns_raw():
    eps = extract_endpoints('fetch("/api/x")')
    assert eps == ["/api/x"]


# ── تحليل الصفحة: scripts + inline ──

def test_parse_page_scripts():
    html = '<script src="/a.js"></script><script>fetch("/inline/ep")</script>'
    pg = parse_page(html, "https://app.example.com/")
    assert pg.scripts == ["https://app.example.com/a.js"]
    assert any("inline/ep" in s for s in pg.inline_scripts)


# ── الزحف: يقرأ كل JS ويجمع الـ endpoints ──

def test_discover_js_reads_all_scripts():
    pages = {
        "https://app.example.com/": (
            '<script src="/app.js"></script>'
            '<script src="https://app.example.com/vendor.js"></script>'
            '<script>fetch("/inline/here")</script>'
        ),
        "https://app.example.com/app.js": 'fetch("/api/users"); fetch("/api/orders/1")',
        "https://app.example.com/vendor.js": 'axios.get("/api/products")',
    }

    def fetch(url):
        return Fetched(200, pages.get(url, ""), url)

    disc = discover_js_endpoints(["https://app.example.com/"], fetch, _RULES)
    assert set(disc.scripts_read) == {
        "https://app.example.com/app.js", "https://app.example.com/vendor.js"}
    for ep in ("/api/users", "/api/orders/1", "/api/products", "/inline/here"):
        assert f"https://app.example.com{ep}" in disc.endpoints


def test_discover_js_stays_in_scope():
    pages = {"https://app.example.com/": '<script src="https://cdn.other.com/x.js"></script>'}
    read = []

    def fetch(url):
        read.append(url)
        return Fetched(200, pages.get(url, ""), url)

    disc = discover_js_endpoints(["https://app.example.com/"], fetch, _RULES)
    assert "https://cdn.other.com/x.js" not in read    # سكربت طرف ثالث لا يُجلب
    assert disc.scripts_read == []


# ── تخزين الـ endpoints على المضيفات ──

def _program(db):
    p = Program(name="D", handle="demo")
    p.scope_assets = [ScopeAsset(kind=AssetKind.wildcard, identifier="*.example.com", in_scope=True)]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def test_store_endpoints_merges_into_hosts(db_session):
    p = _program(db_session)
    db_session.add(Host(program_id=p.id, hostname="app.example.com", in_scope=True,
                        is_live=True, urls="https://app.example.com/old"))
    db_session.commit()
    eps = ["https://app.example.com/api/a", "https://app.example.com/api/b",
           "https://evil.com/x"]   # خارج النطاق
    out = store_endpoints(db_session, p, eps)
    assert out["dropped"] == 1
    host = db_session.query(Host).filter_by(hostname="app.example.com").one()
    urls = host.urls.splitlines()
    assert "https://app.example.com/old" in urls
    assert "https://app.example.com/api/a" in urls
    assert db_session.query(AuditLog).filter_by(action="js_endpoints_stored").count() == 1


def test_store_endpoints_creates_missing_host(db_session):
    p = _program(db_session)
    store_endpoints(db_session, p, ["https://api.example.com/v1/x"])
    host = db_session.query(Host).filter_by(hostname="api.example.com").one()
    assert host.in_scope is True and host.source == "js-discovery"
    assert "https://api.example.com/v1/x" in host.urls


# ── السلسلة المصادَقة الكاملة ──

@pytest.fixture
def _key():
    old = settings.field_encryption_key
    settings.field_encryption_key = generate_key()
    yield
    settings.field_encryption_key = old


def test_authenticated_pentest_end_to_end(db_session, _key):
    from workers.auth_pentest import run_authenticated_pentest
    from workers.idor_logic import HttpResponse

    p = Program(name="D", handle="demo", allow_account_provisioning=True,
                account_email_domain="r.test")
    p.scope_assets = [ScopeAsset(kind=AssetKind.domain, identifier="app.example.com", in_scope=True)]
    db_session.add(p)
    db_session.commit()
    db_session.refresh(p)

    reg_html = ('<form action="/users" method="post">'
                '<input name=email type=email><input name=password type=password></form>')

    def page_fetch(url):
        from workers.form_discovery import FetchResult
        return FetchResult(200, reg_html, url) if url.endswith("/register") else FetchResult(404)

    def js_fetch(url):
        if url.rstrip("/") == "https://app.example.com":
            return Fetched(200, '<script src="/app.js"></script>', url)
        if url.endswith("/app.js"):
            return Fetched(200, 'fetch("/api/orders/1")', url)
        return Fetched(404, "", url)

    def register_fn(req):
        return RegisterResult(200, "ok", cookies={"sid": req.data["email"]})

    accta = {}

    def idor_requester(sess, url):
        # الحساب A يملك /api/orders/1؛ وجلسة B تقراه => IDOR.
        if sess and sess.label:
            # نضمن أن marker (بريد A) يظهر في الرد.
            return HttpResponse(200, "owner " + accta.get("email", ""))
        return HttpResponse(403, "")

    # نحتاج بريد A كـ marker — يُقرأ بعد الإنشاء.
    out = run_authenticated_pentest(
        db_session, p, "app.example.com",
        page_fetch=page_fetch, js_fetch=js_fetch, register_fn=register_fn,
        idor_requester=idor_requester, rules=[ScopeRule("domain", "app.example.com", True)],
    )
    from api.models.account import ProvisionedAccount
    a = db_session.query(ProvisionedAccount).order_by(ProvisionedAccount.label).first()
    accta["email"] = a.identifier

    assert out["accounts"]["idor-a"] == "created"
    assert out["js"]["stored"] >= 1           # endpoint مخزّن من JS
    host = db_session.query(Host).filter_by(hostname="app.example.com").one()
    assert "https://app.example.com/api/orders/1" in host.urls


def test_authenticated_pentest_captcha_no_bypass(db_session, _key):
    from workers.auth_pentest import run_authenticated_pentest
    from workers.form_discovery import FetchResult
    from workers.idor_logic import HttpResponse

    p = Program(name="D", handle="demo", allow_account_provisioning=True,
                account_email_domain="r.test")
    p.scope_assets = [ScopeAsset(kind=AssetKind.domain, identifier="app.example.com", in_scope=True)]
    db_session.add(p)
    db_session.commit()
    db_session.refresh(p)

    reg_html = ('<form action="/u"><input name=email type=email>'
                '<input name=password type=password><div class="g-recaptcha"></div></form>')
    out = run_authenticated_pentest(
        db_session, p, "app.example.com",
        page_fetch=lambda u: FetchResult(200, reg_html, u) if u.endswith("/register") else FetchResult(404),
        js_fetch=lambda u: Fetched(404, "", u),
        register_fn=lambda req: RegisterResult(200, "ok"),
        idor_requester=lambda s, u: HttpResponse(404),
        rules=[ScopeRule("domain", "app.example.com", True)],
    )
    assert out["captcha"] == "recaptcha"
    assert "captcha_blocked" in out["accounts"]        # لم يُنشأ حساب — لا تخطٍّ
    assert "يلزم حسابان" in out["idor"]
