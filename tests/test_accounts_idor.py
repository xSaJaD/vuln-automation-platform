"""اختبارات إنشاء الحسابات التلقائي + الفحص التفاضلي لـ IDOR."""

import json

import pytest

from api.config import settings
from api.models.account import ProvisionedAccount
from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.scan import ScanStatus
from api.services.crypto import generate_key
from api.services.scope_matching import ScopeRule
from workers.account_logic import (
    DEFAULT_ACCOUNTS,
    MAX_ACCOUNTS,
    AccountRecipe,
    RegisterResult,
    make_identity,
    provision_accounts,
)
from workers.idor_db import run_idor
from workers.idor_logic import HttpResponse, OwnedResource, Session, find_idor


@pytest.fixture(autouse=True)
def _cipher_key():
    old = settings.field_encryption_key
    settings.field_encryption_key = generate_key()
    yield
    settings.field_encryption_key = old


def _program(db, *, allow=True, domain="researcher.test", rate=None):
    p = Program(name="Demo", handle="demo", allow_account_provisioning=allow,
                account_email_domain=domain, rate_limit_per_min=rate)
    p.scope_assets = [ScopeAsset(kind=AssetKind.domain, identifier="app.example.com", in_scope=True)]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _recipe(**kw):
    base = dict(register_url="https://app.example.com/register", success_marker="welcome")
    base.update(kw)
    return AccountRecipe(**base)


def _ok_register(req):
    return RegisterResult(status_code=200, body="welcome!", cookies={"sid": "abc"})


# ── الحواجز ──

def test_provision_blocked_without_roe(db_session):
    p = _program(db_session, allow=False)
    with pytest.raises(PermissionError):
        provision_accounts(db_session, p, _recipe(), _ok_register)
    assert db_session.query(AuditLog).filter_by(action="account_provision_block").count() == 1
    assert db_session.query(ProvisionedAccount).count() == 0


def test_provision_blocked_out_of_scope(db_session):
    p = _program(db_session)
    recipe = _recipe(register_url="https://evil.com/register")
    with pytest.raises(PermissionError):
        provision_accounts(db_session, p, recipe, _ok_register)
    assert db_session.query(AuditLog).filter_by(action="account_scope_check", decision="deny").count() == 1


def test_provision_requires_email_domain(db_session):
    p = _program(db_session, domain=None)
    with pytest.raises(ValueError):
        make_identity(p, "idor-a")


def test_count_is_capped(db_session):
    p = _program(db_session)
    accts = provision_accounts(db_session, p, _recipe(), _ok_register, count=99)
    assert len(accts) == MAX_ACCOUNTS


# ── الإنشاء الناجح ──

def test_provision_creates_two_accounts_encrypted(db_session):
    p = _program(db_session)
    accts = provision_accounts(db_session, p, _recipe(), _ok_register)
    assert len(accts) == DEFAULT_ACCOUNTS
    assert [a.label for a in accts] == ["idor-a", "idor-b"]
    assert all(a.status == "created" for a in accts)
    # السرّ مشفّر ومختلف عن النص الصريح، والمعرّفات فريدة.
    assert all(a.secret_encrypted and "password" not in a.secret_encrypted for a in accts)
    assert accts[0].identifier != accts[1].identifier
    assert accts[0].identifier.endswith("@researcher.test")
    # جلسة ملتقطة.
    from api.services.crypto import get_cipher
    sess = json.loads(get_cipher().decrypt(accts[0].session_encrypted))
    assert sess["cookies"] == {"sid": "abc"}
    assert db_session.query(AuditLog).filter_by(action="account_provision", decision="allow").count() == 2


def test_registration_failure_recorded_not_claimed_success(db_session):
    p = _program(db_session)

    def bad(req):
        return RegisterResult(status_code=400, body="error")

    accts = provision_accounts(db_session, p, _recipe(), bad)
    assert all(a.status == "failed" for a in accts)
    assert all(a.secret_encrypted is None for a in accts)


def test_register_exception_is_failed_not_success(db_session):
    p = _program(db_session)

    def boom(req):
        raise ConnectionError("down")

    accts = provision_accounts(db_session, p, _recipe(), boom)
    assert all(a.status == "failed" for a in accts)
    assert db_session.query(AuditLog).filter_by(action="account_provision", decision="error").count() == 2


def test_rate_limit_delay_between_accounts(db_session):
    p = _program(db_session, rate=60)   # => تأخير ثانية بين الطلبات
    slept = []
    provision_accounts(db_session, p, _recipe(), _ok_register, sleep=slept.append)
    assert slept == [1.0]               # تأخير واحد بين حسابين


def test_login_flow_used_for_session(db_session):
    p = _program(db_session)
    calls = []

    def reg(req):
        calls.append(req.url)
        if req.url.endswith("/login"):
            return RegisterResult(status_code=200, cookies={"auth": "t"})
        return RegisterResult(status_code=200, body="welcome")  # تسجيل بلا كوكيز

    recipe = _recipe(login_url="https://app.example.com/login")
    accts = provision_accounts(db_session, p, recipe, reg)
    assert all(a.status == "created" for a in accts)
    assert any(u.endswith("/login") for u in calls)


# ── منطق IDOR التفاضلي ──

_RULES = [ScopeRule(kind="domain", identifier="app.example.com", in_scope=True)]


def test_idor_detects_cross_account_access():
    resources = [OwnedResource(url="https://app.example.com/orders/1", owner_label="idor-a",
                               marker="alice-secret")]
    sessions = [Session("idor-a", {"sid": "a"}), Session("idor-b", {"sid": "b"}), Session(None)]

    def requester(sess, url):
        # B يرى بيانات A => IDOR؛ المجهول محجوب.
        if sess.label is None:
            return HttpResponse(403, "")
        return HttpResponse(200, "order of alice-secret")

    hits = find_idor(resources, sessions, requester, _RULES)
    assert len(hits) == 1
    assert hits[0].vuln_class == "idor" and hits[0].accessor_label == "idor-b"


def test_idor_public_resource_is_broken_access_control():
    resources = [OwnedResource("https://app.example.com/doc/9", "idor-a", "topsecret")]
    sessions = [Session("idor-a"), Session("idor-b"), Session(None)]
    hits = find_idor(resources, sessions, lambda s, u: HttpResponse(200, "topsecret"), _RULES)
    assert len(hits) == 1
    assert hits[0].vuln_class == "broken-access-control" and hits[0].accessor_label is None


def test_idor_no_finding_when_isolated():
    resources = [OwnedResource("https://app.example.com/orders/1", "idor-a", "alice-secret")]
    sessions = [Session("idor-a"), Session("idor-b"), Session(None)]

    def requester(sess, url):
        return HttpResponse(200, "alice-secret") if sess.label == "idor-a" else HttpResponse(403, "")

    assert find_idor(resources, sessions, requester, _RULES) == []


def test_idor_out_of_scope_resource_skipped():
    resources = [OwnedResource("https://evil.com/orders/1", "idor-a", "x")]
    sessions = [Session("idor-a"), Session("idor-b")]
    blocked = []
    hits = find_idor(resources, sessions, lambda s, u: HttpResponse(200, "x"), _RULES,
                     on_scope_block=lambda url, d: blocked.append(url))
    assert hits == [] and blocked == ["https://evil.com/orders/1"]


# ── ربط IDOR بقاعدة البيانات ──

def _provision(db, p):
    return provision_accounts(db, p, _recipe(), _ok_register)


def test_run_idor_persists_findings(db_session):
    p = _program(db_session)
    _provision(db_session, p)
    resources = [OwnedResource("https://app.example.com/orders/1", "idor-a", "secret")]

    def requester(sess, url):
        return HttpResponse(200, "secret") if sess.label else HttpResponse(403, "")

    scan_run, findings = run_idor(db_session, p, resources, requester)
    assert scan_run.status == ScanStatus.done and scan_run.outcome == "findings"
    assert len(findings) == 1
    assert findings[0].source_tool == "idor" and findings[0].cwe == "CWE-639"


def test_run_idor_needs_two_accounts(db_session):
    p = _program(db_session)   # لا حسابات
    scan_run, findings = run_idor(db_session, p, [], lambda s, u: HttpResponse(200))
    assert scan_run.status == ScanStatus.failed and findings == []
    assert "حسابان" in scan_run.error


# ── طبقة الـ API ──

def test_api_provision_requires_roe_and_domain(client, db_session):
    p = Program(name="D", handle="d")
    p.scope_assets = [ScopeAsset(kind=AssetKind.domain, identifier="app.example.com", in_scope=True)]
    db_session.add(p)
    db_session.commit()
    body = {"recipe": {"register_url": "https://app.example.com/register"}}
    # ROE مُعطَّل => 403
    assert client.post(f"/programs/{p.id}/accounts/provision", json=body).status_code == 403

    p.allow_account_provisioning = True
    db_session.commit()
    # لا نطاق بريد => 422
    assert client.post(f"/programs/{p.id}/accounts/provision", json=body).status_code == 422


def test_api_idor_blocks_out_of_scope_resource(client, db_session):
    p = _program(db_session)
    body = {"resources": [{"url": "https://evil.com/x", "owner_label": "idor-a", "marker": "m"}]}
    assert client.post(f"/programs/{p.id}/idor", json=body).status_code == 403
