"""اختبارات الفجوات الجديدة: OOB (blind)، Stored XSS، زحف SPA، وقياس الدقّة corpus."""

import urllib.parse

from api.services.scope_matching import ScopeRule
from workers.oob import Interaction
from workers.oob_confirm import confirm_blind_rce, confirm_blind_ssrf, pick_oob_confirmer
from workers.spa_crawl import RenderedPage, crawl_spa
from workers.stored_xss import StoredXssProbe, confirm_stored_xss

_RULES = [ScopeRule(kind="domain", identifier="app.example.com", in_scope=True),
          ScopeRule(kind="wildcard", identifier="*.example.com", in_scope=True)]
_NOW = lambda _: None  # noqa: E731  (بلا انتظار في الاختبار)


# ── OOB / blind ──

class _FakeOob:
    """بيئة OOB وهمية: probe يرسل الطلب، والخادم يسجّل الـ callback إن كان الهدف مصابًا."""

    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable
        self._payloads: dict[str, str] = {}
        self._hits: set[str] = set()

    def domain(self):
        return "oast.test"

    def new_payload(self):
        uid = f"id{len(self._payloads)}"
        host = f"{uid}.oast.test"
        self._payloads[uid] = host
        return uid, host

    def poll(self):
        return [Interaction("dns", uid) for uid in self._hits]

    def receive(self, url):
        for uid, host in self._payloads.items():
            if host in url and self.vulnerable:
                self._hits.add(uid)


class _OobProbe:
    def __init__(self, oob):
        self.oob = oob

    def get(self, url):
        self.oob.receive(url)   # يحاكي وصول الطلب لخادم OOB
        return None


def test_blind_ssrf_confirmed_on_callback():
    oob = _FakeOob(vulnerable=True)
    v = confirm_blind_ssrf(_OobProbe(oob), oob, "https://app.example.com/fetch", "url",
                           sleep=_NOW, tries=2)
    assert v.status == "confirmed" and "SSRF" in v.signal


def test_blind_ssrf_unconfirmed_without_callback():
    oob = _FakeOob(vulnerable=False)
    v = confirm_blind_ssrf(_OobProbe(oob), oob, "https://app.example.com/fetch", "url",
                           sleep=_NOW, tries=2)
    assert v.status == "unconfirmed"


def test_blind_rce_confirmed():
    oob = _FakeOob(vulnerable=True)
    v = confirm_blind_rce(_OobProbe(oob), oob, "https://app.example.com/ping", "host",
                          sleep=_NOW, tries=2)
    assert v.status == "confirmed" and "RCE" in v.signal


def test_pick_oob_confirmer():
    assert pick_oob_confirmer("ssrf") is confirm_blind_ssrf
    assert pick_oob_confirmer("OS Command Injection") is confirm_blind_rce
    assert pick_oob_confirmer("xss") is None


# ── Stored XSS ──

class _Resp:
    def __init__(self, text):
        self.text = text


class _StoreProbe:
    """يخزّن ما يُحقن في نقطة الكتابة، ويعكسه في صفحات القراءة (مُرمَّزًا أو لا)."""

    def __init__(self, vulnerable=True, encode=False):
        self.vulnerable = vulnerable
        self.encode = encode
        self.stored = ""

    def get(self, url):
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        if "c" in q:                          # نقطة الكتابة (المعامل c)
            self.stored = q["c"][-1]
            return _Resp("saved")
        if self.vulnerable and self.stored:   # صفحة قراءة
            shown = self.stored.replace("<", "&lt;") if self.encode else self.stored
            return _Resp(f"<html>{shown}</html>")
        return _Resp("<html>empty</html>")


def _spec():
    return StoredXssProbe(write_url="https://app.example.com/comment", write_param="c",
                          read_urls=["https://app.example.com/thread"])


def test_stored_xss_confirmed():
    v = confirm_stored_xss(_StoreProbe(vulnerable=True, encode=False), _spec())
    assert v.status == "confirmed" and "مخزّن" in v.signal


def test_stored_xss_encoded_is_safe():
    v = confirm_stored_xss(_StoreProbe(vulnerable=True, encode=True), _spec())
    assert v.status == "unconfirmed"       # ظهر لكن مُرمَّزًا => ليس ثغرة


def test_stored_xss_not_reflected():
    v = confirm_stored_xss(_StoreProbe(vulnerable=False), _spec())
    assert v.status == "unconfirmed"


# ── زحف SPA ──

def test_spa_crawl_collects_xhr_and_links_in_scope():
    pages = {
        "https://app.example.com": RenderedPage(
            200,
            links=["https://app.example.com/dashboard", "https://evil.com/x"],
            xhr=["https://app.example.com/api/me", "https://tracker.com/t"]),
        "https://app.example.com/dashboard": RenderedPage(
            200, xhr=["https://app.example.com/api/orders"]),
    }

    def render(url, cookies):
        return pages.get(url, RenderedPage(0))

    res = crawl_spa("app.example.com", render, _RULES)
    assert "https://app.example.com/api/me" in res.endpoints
    assert "https://app.example.com/api/orders" in res.endpoints     # من صفحة تابعتها
    assert "https://app.example.com/dashboard" in res.endpoints
    assert not any("evil.com" in e or "tracker.com" in e for e in res.endpoints)


def test_spa_crawl_passes_cookies():
    seen = {}

    def render(url, cookies):
        seen["cookies"] = cookies
        return RenderedPage(200)

    crawl_spa("app.example.com", render, _RULES, cookies={"sid": "abc"})
    assert seen["cookies"] == {"sid": "abc"}


# ── benchmark corpus (دليل الدقّة داخل CI) ──

def test_accuracy_corpus_precision_recall():
    """يمرّر مجموعة نتائج معروفة عبر منطق التطبيع ويقيس precision/recall.

    دليل قابل للتكرار داخل CI أن منطق الدقّة (التطبيع/المفتاح) لا ينحرف.
    """
    from api.services.benchmark import finding_key, score

    # الحقيقة الأرضية لهدف اختباري (host, class, endpoint).
    ground_truth = {
        finding_key("sqli", "app.example.com", "/login?u"),
        finding_key("xss", "app.example.com", "/search?q"),
        finding_key("idor", "app.example.com", "/api/orders/1"),
        finding_key("ssrf", "app.example.com", "/fetch?url"),
    }
    # ما اكتشفته المنصّة (بأسماء أدوات مختلفة — يجب أن تتطبّع لنفس المفاتيح).
    raw = [
        ("SQL Injection", "app.example.com", "/login?u=1"),
        ("generic-sqli", "app.example.com", "/login?u=2"),      # تكرار → يُدمج
        ("Reflected Cross-Site Scripting", "app.example.com", "/search?q=x"),
        ("idor", "app.example.com", "/api/orders/1"),
        ("Server-Side Request Forgery", "app.example.com", "/fetch?url=x"),
    ]
    found = {finding_key(t, h, e) for (t, h, e) in raw}
    s = score(found, ground_truth)
    assert s.recall == 1.0            # كل ثغرات الحقيقة الأرضية اكتُشفت
    assert s.precision == 1.0         # بلا إيجابيات كاذبة (التكرار اندمج)
    assert s.f1 == 1.0
