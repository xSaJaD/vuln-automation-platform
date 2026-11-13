"""مُنفِّذ HTTP الحقيقي لإنشاء الحسابات وجلب الجلسات — يعمل داخل الـ worker.

يُحقَن في account_logic.provision_accounts كـ register_fn. يستخدم httpx مع
جرّة كوكيز حتى تُلتقط جلسة الحساب بعد التسجيل/الدخول.
"""

from __future__ import annotations

import httpx

from api.services.captcha_detect import detect_captcha
from api.services.html_forms import parse
from workers.account_logic import CAPTCHA_SENTINEL, RegisterRequest, RegisterResult

USER_AGENT = "vuln-automation-platform/idor-tester"
TIMEOUT = 30.0


def _extract_token(body: str, headers) -> str | None:
    auth = headers.get("authorization") or headers.get("x-auth-token")
    return auth or None


def register_over_http(req: RegisterRequest) -> RegisterResult:
    """ينفّذ طلب تسجيل/دخول واحدًا ويرجّع الحالة + الكوكيز."""
    with httpx.Client(
        follow_redirects=False, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}
    ) as client:
        data = dict(req.data)
        # إعادة جلب صفحة النموذج أولًا: التقاط حقول CSRF الطازجة + كشف CAPTCHA.
        if req.prefetch_url:
            page = client.get(req.prefetch_url)
            provider = detect_captcha(page.text)
            if provider:
                # لا تخطٍّ — يُبلَّغ للأعلى ويُوقف الإنشاء.
                return RegisterResult(status_code=-1, body=f"{CAPTCHA_SENTINEL}:{provider}")
            forms, _ = parse(page.text, req.prefetch_url)
            for form in forms:
                for name, value in form.hidden().items():
                    if name not in data or not data[name]:
                        data[name] = value
        if req.method == "GET":
            resp = client.get(req.url, params=data)
        elif req.content_type == "json":
            resp = client.post(req.url, json=data)
        else:
            resp = client.post(req.url, data=data)
        return RegisterResult(
            status_code=resp.status_code,
            body=resp.text[:20000],
            cookies=dict(resp.cookies),
            token=_extract_token(resp.text, resp.headers),
        )


def make_idor_requester():
    """يرجّع requester(session, url) لـ idor_logic باستخدام كوكيز/توكن الجلسة."""
    from workers.idor_logic import HttpResponse, Session

    def requester(session: Session, url: str) -> HttpResponse:
        headers = {"User-Agent": USER_AGENT}
        if session and session.token:
            headers["Authorization"] = session.token
        cookies = session.cookies if session else {}
        with httpx.Client(
            follow_redirects=False, timeout=TIMEOUT, headers=headers, cookies=cookies
        ) as client:
            resp = client.get(url)
            return HttpResponse(status_code=resp.status_code, body=resp.text[:50000])

    return requester


def make_page_fetcher():
    """يرجّع fetch(url) -> FetchResult لاكتشاف نموذج التسجيل (زحف مجهول)."""
    from workers.form_discovery import FetchResult

    def fetch(url: str) -> FetchResult:
        with httpx.Client(
            follow_redirects=True, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}
        ) as client:
            resp = client.get(url)
            return FetchResult(status_code=resp.status_code, html=resp.text[:200000],
                               final_url=str(resp.url))

    return fetch


def make_js_fetcher():
    """يرجّع fetch(url) -> Fetched لاستخراج الـ endpoints من JS (GET يتبع التحويلات)."""
    from workers.js_discovery import Fetched

    def fetch(url: str) -> Fetched:
        with httpx.Client(
            follow_redirects=True, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}
        ) as client:
            resp = client.get(url)
            return Fetched(status_code=resp.status_code, body=resp.text[:500000],
                           final_url=str(resp.url))

    return fetch


def make_spec_fetchers():
    """يرجّع (fetch, post) لاكتشاف مواصفات API (GET + POST introspection)."""
    from workers.api_spec import Fetched

    def fetch(url: str) -> Fetched:
        with httpx.Client(follow_redirects=True, timeout=TIMEOUT,
                          headers={"User-Agent": USER_AGENT}) as c:
            r = c.get(url)
            return Fetched(r.status_code, r.text[:1000000])

    def post(url: str, body: str) -> Fetched:
        with httpx.Client(follow_redirects=False, timeout=TIMEOUT,
                          headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"}) as c:
            r = c.post(url, content=body)
            return Fetched(r.status_code, r.text[:200000])

    return fetch, post


def make_probe_requester(headers=None):
    """يرجّع requester(url) -> ProbeResponse لفحص المعاملات (GET يحمل الحقن)."""
    from workers.param_fuzz import ProbeResponse

    def requester(url: str) -> ProbeResponse:
        with httpx.Client(follow_redirects=False, timeout=TIMEOUT,
                          headers={"User-Agent": USER_AGENT, **(headers or {})}) as c:
            r = c.get(url)
            return ProbeResponse(status_code=r.status_code, body=r.text[:200000],
                                 location=r.headers.get("location", ""))

    return requester


def make_method_requester():
    """يرجّع requester(session, url, method) -> MethodResponse لفحص التحكّم بالوصول."""
    from workers.access_control import MethodResponse

    def requester(session, url: str, method: str) -> MethodResponse:
        headers = {"User-Agent": USER_AGENT}
        if session and session.token:
            headers["Authorization"] = session.token
        cookies = session.cookies if session else {}
        with httpx.Client(follow_redirects=False, timeout=TIMEOUT,
                          headers=headers, cookies=cookies) as c:
            r = c.request(method, url)
            return MethodResponse(status_code=r.status_code, body=r.text[:50000])

    return requester
