"""اختبارات التطويرات العميقة: أسرار، source maps، API spec، مقارنة IDOR،
تصعيد صلاحيات، فحص معاملات، قياس الدقّة، والفحص التفاضلي."""

import pytest

from api.config import settings
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.recon import Host
from api.services.benchmark import finding_key, score
from api.services.crypto import generate_key
from api.services.scope_matching import ScopeRule
from api.services.secret_scan import scan_secrets
from api.services.similarity import is_same_resource, ratio
from workers.access_control import find_privilege_issues, is_sensitive
from workers.account_logic import AccountRecipe, RegisterResult, provision_accounts
from workers.api_spec import discover_api_spec, parse_openapi
from workers.delta import diff, fingerprint_hosts
from workers.idor_logic import HttpResponse, OwnedResource, Session, find_idor_compare
from workers.param_fuzz import ProbeResponse, discover_hidden_params, fuzz_param
from workers.sourcemap import parse_sourcemap, sourcemap_url_for

_RULES = [ScopeRule(kind="domain", identifier="app.example.com", in_scope=True),
          ScopeRule(kind="wildcard", identifier="*.example.com", in_scope=True)]


# ── كشف الأسرار ──

def test_secret_scan_detects_keys():
    # تُبنى ديناميكيًا حتى لا تُحفَظ كأسرار حرفية (يحجبها فحص أسرار GitHub).
    stripe = "sk_" + "live_" + "abcdefghij1234567890ABCD"
    aws = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    gkey = "AIza" + "SyB3kR8vN2pQ7wX1zL9mT4jH6cD0fG5sA2b"
    text = f'var s="{stripe}"; aws="{aws}"; k="{gkey}";'
    kinds = {h.kind for h in scan_secrets(text)}
    assert "stripe_secret" in kinds
    assert "aws_access_key" in kinds
    assert "google_api_key" in kinds


def test_secret_scan_masks_and_ignores_placeholders():
    gh_token = "ghp_" + "0123456789abcdefghij0123456789abcdef"
    hits = scan_secrets(f'token="your-api-key"; real="{gh_token}"')
    assert all("your-api-key" not in h.masked for h in hits)
    gh = [h for h in hits if h.kind == "github_token"]
    assert gh and "…" in gh[0].masked and gh_token[5:] not in gh[0].masked


# ── source maps ──

def test_sourcemap_parse_and_url():
    raw = '{"version":3,"sources":["app.ts"],"sourcesContent":["const api=\\"/api/secret\\""]}'
    sm = parse_sourcemap(raw)
    assert sm.sources == ["app.ts"] and "/api/secret" in sm.contents[0]
    assert sourcemap_url_for("https://a.com/app.js") == "https://a.com/app.js.map"
    assert sourcemap_url_for("https://a.com/app.js", "//# sourceMappingURL=app.js.map") \
        == "https://a.com/app.js.map"
    assert parse_sourcemap("not json") is None


# ── API spec ──

def test_parse_openapi_endpoints_and_params():
    doc = ('{"servers":[{"url":"/api/v2"}],"paths":{"/users/{id}":'
           '{"get":{"parameters":[{"name":"id"}]},"delete":{}}}}')
    eps = parse_openapi(doc, "https://app.example.com/openapi.json")
    methods = {e.method for e in eps}
    assert methods == {"GET", "DELETE"}
    assert any(e.url.endswith("/api/v2/users/{id}") and e.params == ["id"] for e in eps)


def test_discover_api_spec_and_graphql():
    openapi = '{"paths":{"/a":{"get":{}}}}'

    def fetch(url):
        from workers.api_spec import Fetched
        return Fetched(200, openapi) if url.endswith("/openapi.json") else Fetched(404)

    def post(url, body):
        from workers.api_spec import Fetched
        return Fetched(200, '{"data":{"__schema":{"queryType":{"name":"Query"}}}}') \
            if url.endswith("/graphql") else Fetched(404)

    res = discover_api_spec("app.example.com", fetch, post, _RULES)
    assert res.spec_url.endswith("/openapi.json")
    assert res.graphql_introspection is True


# ── مقارنة الردود / IDOR ──

def test_similarity_ratio_and_same_resource():
    assert ratio("hello world", "hello world") == 1.0
    assert is_same_resource("alice secret data here", "alice secret data here", "not found") is True
    assert is_same_resource("alice data", "forbidden", "forbidden") is False


def test_find_idor_compare_detects_without_marker():
    resources = [OwnedResource("https://app.example.com/orders/5", "idor-a", "")]
    sessions = [Session("idor-a", {"s": "a"}), Session("idor-b", {"s": "b"}), Session(None)]

    def requester(sess, url):
        if "999999999" in url:
            return HttpResponse(404, "error not found page")
        if sess and sess.label:
            return HttpResponse(200, "order #5 total $500 customer alice full details")
        return HttpResponse(403, "")

    hits = find_idor_compare(resources, sessions, requester, _RULES)
    assert len(hits) == 1 and hits[0].accessor_label == "idor-b"


def test_find_idor_compare_safe_when_b_gets_error():
    resources = [OwnedResource("https://app.example.com/orders/5", "idor-a", "")]
    sessions = [Session("idor-a"), Session("idor-b")]

    def requester(sess, url):
        if "999999999" in url:
            return HttpResponse(404, "error")
        return HttpResponse(200, "secret") if sess.label == "idor-a" else HttpResponse(403, "error")

    assert find_idor_compare(resources, sessions, requester, _RULES) == []


# ── تصعيد الصلاحيات ──

def test_is_sensitive():
    assert is_sensitive("https://app.example.com/admin/users")
    assert is_sensitive("https://app.example.com/api/accounts/1")
    assert not is_sensitive("https://app.example.com/home")


def test_privilege_escalation_detected():
    from workers.access_control import MethodResponse
    endpoints = ["https://app.example.com/admin/users", "https://app.example.com/public"]

    def requester(sess, url, method):
        # المستخدم العادي (له label) يرى الإدارة؛ المجهول (label=None) محجوب.
        if "/admin/" in url and method == "GET" and sess.label:
            return MethodResponse(200, "all users listed")
        return MethodResponse(403)

    hits = find_privilege_issues(endpoints, Session("idor-b", {"s": "b"}), requester, _RULES,
                                 anon=Session(None))
    assert len(hits) == 1
    assert hits[0].vuln_class == "privilege-escalation"


def test_privilege_public_admin_is_broken_access():
    from workers.access_control import MethodResponse
    hits = find_privilege_issues(
        ["https://app.example.com/admin/config"], Session("idor-b"),
        lambda s, u, m: MethodResponse(200, "x") if m == "GET" else MethodResponse(403),
        _RULES, anon=Session(None))
    assert hits[0].vuln_class == "broken-access-control"   # المجهول وصله أيضًا


# ── فحص المعاملات ──

def test_fuzz_param_reflected_xss():
    def requester(url):
        from urllib.parse import unquote
        # ينعكس المدخل حرفيًا.
        val = unquote(url.split("q=", 1)[1]) if "q=" in url else ""
        return ProbeResponse(200, f"<html>results for {val}</html>")

    hits = fuzz_param("https://app.example.com/s?q=1", "q", requester)
    assert any(h.vuln_class == "xss" for h in hits)


def test_fuzz_param_sql_error():
    def requester(url):
        from urllib.parse import unquote
        val = unquote(url.split("id=", 1)[1]) if "id=" in url else ""
        if "'" in val:
            return ProbeResponse(500, "You have an error in your SQL syntax near")
        return ProbeResponse(200, "ok")

    hits = fuzz_param("https://app.example.com/u?id=1", "id", requester)
    assert any(h.vuln_class == "sqli" for h in hits)


def test_fuzz_param_open_redirect():
    def requester(url):
        from urllib.parse import unquote
        val = unquote(url.split("next=", 1)[1]) if "next=" in url else ""
        if val.startswith("https://canary-redirect.test"):
            return ProbeResponse(302, "", location=val)
        return ProbeResponse(200, "")

    hits = fuzz_param("https://app.example.com/go?next=/home", "next", requester)
    assert any(h.vuln_class == "open-redirect" for h in hits)


def test_discover_hidden_params():
    def requester(url):
        # 'debug' يغيّر الرد كثيرًا؛ الباقي ثابت.
        if "debug=" in url:
            return ProbeResponse(200, "x" * 500 + " DEBUG MODE verbose stack trace")
        return ProbeResponse(200, "x" * 100)

    found = discover_hidden_params("https://app.example.com/p", requester)
    assert "debug" in found


# ── قياس الدقّة ──

def test_benchmark_score():
    found = {finding_key("xss", "a.com", "/x"), finding_key("sqli", "a.com", "/y")}
    expected = {finding_key("xss", "a.com", "/x"), finding_key("idor", "a.com", "/z")}
    s = score(found, expected)
    assert s.true_positives == 1 and s.false_positives == 1 and s.false_negatives == 1
    assert s.precision == 0.5 and s.recall == 0.5


def test_benchmark_perfect():
    k = {finding_key("xss", "a.com", "/x")}
    s = score(k, k)
    assert s.precision == 1.0 and s.recall == 1.0 and s.f1 == 1.0


# ── الفحص التفاضلي ──

def test_delta_fingerprint_and_diff():
    class H:
        def __init__(self, name, urls="", tech=None, ports=None):
            self.hostname, self.urls, self.tech, self.open_ports = name, urls, tech, ports

    prev = fingerprint_hosts([H("a.example.com", "https://a.example.com/1")])
    cur = fingerprint_hosts([
        H("a.example.com", "https://a.example.com/1\nhttps://a.example.com/2"),
        H("new.example.com", "https://new.example.com/"),
    ])
    d = diff(prev, cur)
    assert d["changed"] is True
    assert "https://a.example.com/2" in d["new_urls"]
    assert "new.example.com" in d["new_hosts"]


def test_delta_db_first_run(db_session):
    from workers.delta_db import snapshot_and_diff
    p = Program(name="D", handle="demo")
    p.scope_assets = [ScopeAsset(kind=AssetKind.domain, identifier="app.example.com", in_scope=True)]
    db_session.add(p)
    db_session.commit()
    db_session.refresh(p)
    db_session.add(Host(program_id=p.id, hostname="app.example.com", in_scope=True,
                        urls="https://app.example.com/a"))
    db_session.commit()
    out = snapshot_and_diff(db_session, p)
    assert out["first_run"] is True
    # تشغيل ثانٍ بعد رابط جديد => يرصد الجديد فقط.
    h = db_session.query(Host).first()
    h.urls += "\nhttps://app.example.com/b"
    db_session.commit()
    out2 = snapshot_and_diff(db_session, p)
    assert out2["new_urls"] == ["https://app.example.com/b"]


# ── التكامل: ترويسات المصادقة من حساب مُنشأ ──

@pytest.fixture
def _key():
    old = settings.field_encryption_key
    settings.field_encryption_key = generate_key()
    yield
    settings.field_encryption_key = old


def test_auth_headers_from_account(db_session, _key):
    from workers.auth_session import auth_headers_for
    p = Program(name="D", handle="demo", allow_account_provisioning=True,
                account_email_domain="r.test")
    p.scope_assets = [ScopeAsset(kind=AssetKind.domain, identifier="app.example.com", in_scope=True)]
    db_session.add(p)
    db_session.commit()
    db_session.refresh(p)
    provision_accounts(db_session, p,
                       AccountRecipe(register_url="https://app.example.com/r", success_marker="ok"),
                       lambda req: RegisterResult(200, "ok", cookies={"sid": "XYZ"}))
    headers = auth_headers_for(db_session, p.id, "idor-a")
    assert headers.get("Cookie") == "sid=XYZ"
