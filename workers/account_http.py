"""مُنفِّذ HTTP الحقيقي لإنشاء الحسابات وجلب الجلسات — يعمل داخل الـ worker.

يُحقَن في account_logic.provision_accounts كـ register_fn. يستخدم httpx مع
جرّة كوكيز حتى تُلتقط جلسة الحساب بعد التسجيل/الدخول.
"""

from __future__ import annotations

import httpx

from workers.account_logic import RegisterRequest, RegisterResult

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
        if req.method == "GET":
            resp = client.get(req.url, params=req.data)
        elif req.content_type == "json":
            resp = client.post(req.url, json=req.data)
        else:
            resp = client.post(req.url, data=req.data)
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
