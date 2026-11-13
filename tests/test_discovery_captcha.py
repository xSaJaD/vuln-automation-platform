"""اختبارات: كشف CAPTCHA (بلا تخطٍّ)، اكتشاف نموذج التسجيل بالزحف، واكتشاف مراجع IDOR."""

import pytest

from api.config import settings
from api.models.account import ProvisionedAccount
from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset
from api.services.captcha_detect import detect_captcha
from api.services.crypto import generate_key
from api.services.html_forms import parse
from api.services.scope_matching import ScopeRule
from workers.account_logic import CAPTCHA_SENTINEL, RegisterResult, provision_accounts
from workers.form_discovery import FetchResult, discover_registration
from workers.idor_discovery import PageResponse, discover_owned_resources
from workers.idor_logic import Session

_RULES = [ScopeRule(kind="domain", identifier="app.example.com", in_scope=True)]


# ── كشف CAPTCHA ──

def test_detect_captcha_providers():
    assert detect_captcha('<div class="g-recaptcha"></div>') == "recaptcha"
    assert detect_captcha('<script src="https://js.hcaptcha.com/1/api.js">') == "hcaptcha"
    assert detect_captcha('<div class="cf-turnstile"></div>') == "turnstile"
    assert detect_captcha("<p>Please solve the CAPTCHA</p>") == "generic"
    assert detect_captcha("<form><input name=email></form>") is None


# ── تحليل HTML ──

def test_parse_forms_and_hidden_fields():
    html = """<form action="/do" method="post">
      <input name="csrf" type="hidden" value="tok123">
      <input name="email" type="email">
      <input name="password" type="password">
    </form>"""
    forms, _ = parse(html, "https://app.example.com/register")
    assert len(forms) == 1
    assert forms[0].action == "https://app.example.com/do"
    assert forms[0].hidden() == {"csrf": "tok123"}


# ── اكتشاف نموذج التسجيل بالزحف ──

def _page(html):
    return FetchResult(status_code=200, html=html, final_url="")


def test_discover_registration_builds_recipe():
    reg_html = """<form action="/users" method="post">
      <input name="_token" type="hidden" value="abc">
      <input name="email" type="email">
      <input name="username" type="text">
      <input name="password" type="password">
      <input name="password_confirmation" type="password">
    </form>"""

    def fetch(url):
        if url.endswith("/register"):
            return _page(reg_html)
        return FetchResult(status_code=404)

    disc = discover_registration("app.example.com", fetch)
    assert disc.recipe is not None
    r = disc.recipe
    assert r.register_url == "https://app.example.com/users"
    assert r.email_field == "email" and r.password_field == "password"
    assert r.username_field == "username"
    assert r.confirm_password_field == "password_confirmation"
    assert r.fields == {"_token": "abc"}             # CSRF مُلتقَط
    assert r.form_page_url == "https://app.example.com/register"
    assert disc.captcha is None


def test_discover_flags_captcha_without_bypassing():
    html = """<form action="/users" method="post">
      <input name="email" type="email"><input name="password" type="password">
      <div class="g-recaptcha"></div></form>"""

    disc = discover_registration("app.example.com", lambda u: _page(html) if u.endswith("/register") else FetchResult(404))
    assert disc.recipe is not None          # النموذج اكتُشف
    assert disc.captcha == "recaptcha"      # لكن CAPTCHA مُعلَّم — لا تخطٍّ


def test_discover_stays_on_seed_host():
    visited = []

    def fetch(url):
        visited.append(url)
        return FetchResult(404)

    discover_registration("app.example.com", fetch)
    assert all("app.example.com" in u for u in visited)


def test_discover_no_form_found():
    disc = discover_registration("app.example.com", lambda u: FetchResult(404))
    assert disc.recipe is None


# ── التكامل: الزحف → الإنشاء مع CSRF طازج + CAPTCHA يوقف ──

@pytest.fixture
def _key():
    old = settings.field_encryption_key
    settings.field_encryption_key = generate_key()
    yield
    settings.field_encryption_key = old


def _prog(db):
    p = Program(name="D", handle="demo", allow_account_provisioning=True,
                account_email_domain="r.test")
    p.scope_assets = [ScopeAsset(kind=AssetKind.domain, identifier="app.example.com", in_scope=True)]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def test_captcha_halts_provisioning(db_session, _key):
    p = _prog(db_session)
    reg_html = '<form action="/u"><input name=email type=email><input name=password type=password></form>'
    disc = discover_registration("app.example.com",
                                 lambda u: _page(reg_html) if u.endswith("/register") else FetchResult(404))

    # مُنفِّذ يكشف CAPTCHA في الـ prefetch (يحاكي account_http).
    def reg_fn(req):
        return RegisterResult(status_code=-1, body=f"{CAPTCHA_SENTINEL}:recaptcha")

    accts = provision_accounts(db_session, p, disc.recipe, reg_fn)
    assert len(accts) == 1 and accts[0].status == "captcha_blocked"   # توقّف، لم يُنشئ حسابين
    assert db_session.query(AuditLog).filter(
        AuditLog.reason.like("%CAPTCHA%")).count() == 1


# ── اكتشاف مراجع IDOR ──

def test_discover_owned_resources_extracts_object_refs():
    pages = {
        "https://app.example.com/dashboard": """
            <a href="/orders/101">order</a>
            <a href="/orders/102">order</a>
            <a href="/profile/550e8400-e29b-41d4-a716-446655440000">p</a>
            <a href="/about">static</a>
            <a href="/style.css">css</a>""",
    }

    def requester(sess, url):
        return PageResponse(200, pages.get(url, ""))

    sess = Session("idor-a", {"sid": "a"})
    res = discover_owned_resources(sess, "alice@r.test",
                                   ["https://app.example.com/dashboard"], requester, _RULES)
    urls = sorted(r.url for r in res)
    assert "https://app.example.com/orders/101" in urls
    assert "https://app.example.com/orders/102" in urls
    assert any("550e8400" in u for u in urls)             # UUID
    assert not any("/about" in u or ".css" in u for u in urls)   # لا ثابت بلا مرجع
    assert all(r.owner_label == "idor-a" and r.marker == "alice@r.test" for r in res)


def test_discover_owned_resources_respects_scope():
    def requester(sess, url):
        return PageResponse(200, '<a href="https://evil.com/orders/1">x</a>')

    res = discover_owned_resources(Session("idor-a"), "m",
                                   ["https://app.example.com/x"], requester, _RULES)
    assert res == []        # روابط خارج مضيف البذرة تُهمَل


# ── التكامل: auto-IDOR عبر قاعدة البيانات ──

def test_run_auto_idor_end_to_end(db_session, _key):
    from workers.account_logic import AccountRecipe
    from workers.idor_db import run_auto_idor

    p = _prog(db_session)
    recipe = AccountRecipe(register_url="https://app.example.com/register", success_marker="ok")
    provision_accounts(db_session, p, recipe,
                       lambda req: RegisterResult(200, "ok", cookies={"sid": req.data["email"]}))
    assert db_session.query(ProvisionedAccount).filter_by(status="created").count() == 2

    dash = '<a href="/orders/1">o</a>'

    def requester(sess, url):
        # زحف الحساب A يكتشف /orders/1؛ وجلسة B تقراه => IDOR.
        if url.endswith("/dashboard"):
            return PageResponse(200, dash)
        return PageResponse(200, "contains marker") if sess and sess.label else PageResponse(403, "")

    # marker = معرّف A (بريده) — موجود في رد المورد => تقاطع.
    acct_a = db_session.query(ProvisionedAccount).order_by(ProvisionedAccount.label).first()

    def requester2(sess, url):
        if url.endswith("/dashboard"):
            return PageResponse(200, dash)
        body = acct_a.identifier if sess and sess.label else ""
        return PageResponse(200, body) if body else PageResponse(403, "")

    scan_run, findings = run_auto_idor(
        db_session, p, ["https://app.example.com/dashboard"], requester2)
    assert scan_run.status.value == "done"
    assert len(findings) == 1 and findings[0].vuln_class == "idor"
    assert db_session.query(AuditLog).filter_by(action="idor_discover").count() == 1
