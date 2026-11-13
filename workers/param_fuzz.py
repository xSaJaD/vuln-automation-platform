"""فحص المعاملات المتحقَّق (DAST خفيف) + اكتشاف المعاملات المخفية — نقي وقابل للاختبار.

لكل معامل: يحقن payload مميّزًا ويتحقّق من الدليل في الرد (لا تخمين):
  • XSS منعكس: canary فريد ينعكس بلا ترميز.
  • SQLi: رسالة خطأ SQL تظهر بعد ' بينما الرد الطبيعي لا يحويها.
  • Open redirect: وجهة خارجية تظهر في Location.
  • Path traversal: علامة /etc/passwd (root:x:) في الرد.
المعاملات المخفية (أسلوب Arjun): تُرسَل أسماء مرشّحة ويُرصد تغيّر الرد عن الأساس.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit


# استجابة الطلب المحقون: الحالة + الجسم + ترويسة Location (لـ open redirect).
@dataclass
class ProbeResponse:
    status_code: int
    body: str = ""
    location: str = ""


# requester(url) -> ProbeResponse  (الرابط يحمل المعامل المحقون في query)
ProbeRequester = Callable[[str], ProbeResponse]


@dataclass
class ParamFinding:
    url: str
    param: str
    vuln_class: str
    severity: str
    evidence: str


_SQL_ERRORS = (
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "pg_query", "sqlite3.operationalerror", "ora-01756", "psqlexception",
    "sqlstate", "mysql_fetch", "syntax error at or near",
)
# قائمة مصغّرة لأسماء معاملات شائعة قد تكون مخفية.
HIDDEN_PARAM_WORDLIST = (
    "debug", "admin", "test", "id", "user", "user_id", "account", "role", "token",
    "redirect", "url", "next", "callback", "file", "path", "page", "view", "format",
    "preview", "draft", "edit", "source", "raw", "export",
)


def _set_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = parse_qs(parts.query, keep_blank_values=True)
    q[param] = [value]
    return urlunsplit(parts._replace(query=urlencode(q, doseq=True)))


def _params_of(url: str) -> list[str]:
    return list(parse_qs(urlsplit(url).query, keep_blank_values=True).keys())


def fuzz_param(url: str, param: str, requester: ProbeRequester) -> list[ParamFinding]:
    """يحقن payloads متحقَّقة في معامل واحد ويرجّع ما ثبت منها."""
    out: list[ParamFinding] = []
    canary = "xss" + secrets.token_hex(4)

    # 1) XSS منعكس — canary داخل وسم ينعكس حرفيًا.
    xss_payload = f"<{canary}>"
    r = requester(_set_param(url, param, xss_payload))
    if xss_payload in (r.body or ""):
        out.append(ParamFinding(url, param, "xss", "high",
                                f"الحمولة {xss_payload} انعكست بلا ترميز في الرد (XSS منعكس)"))

    # 2) SQLi قائم على الخطأ.
    r_err = requester(_set_param(url, param, "'"))
    body_low = (r_err.body or "").lower()
    if any(e in body_low for e in _SQL_ERRORS):
        r_ok = requester(_set_param(url, param, "1"))
        if not any(e in (r_ok.body or "").lower() for e in _SQL_ERRORS):
            out.append(ParamFinding(url, param, "sqli", "critical",
                                    "رسالة خطأ SQL ظهرت بعد ' ولم تظهر بالقيمة الطبيعية"))

    # 3) Open redirect.
    target = "https://canary-redirect.test/"
    r_red = requester(_set_param(url, param, target))
    loc = (r_red.location or "").lower()
    if r_red.status_code in (301, 302, 303, 307, 308) and loc.startswith(target.lower()):
        out.append(ParamFinding(url, param, "open-redirect", "medium",
                                f"التحويل إلى وجهة خارجية مُتحكَّم بها ({target})"))

    # 4) Path traversal.
    r_lfi = requester(_set_param(url, param, "../../../../etc/passwd"))
    if "root:x:0:0:" in (r_lfi.body or ""):
        out.append(ParamFinding(url, param, "path-traversal", "high",
                                "محتوى /etc/passwd ظهر في الرد (اجتياز مسار)"))
    return out


def fuzz_url(url: str, requester: ProbeRequester) -> list[ParamFinding]:
    """يفحص كل معاملات الرابط الموجودة."""
    out: list[ParamFinding] = []
    for param in _params_of(url):
        out.extend(fuzz_param(url, param, requester))
    return out


def discover_hidden_params(
    url: str, requester: ProbeRequester, *, wordlist=HIDDEN_PARAM_WORDLIST, threshold: int = 40,
) -> list[str]:
    """أسلوب Arjun: معامل يغيّر طول/محتوى الرد جوهريًا عن الأساس = مقبول (مخفي)."""
    base = requester(url)
    base_len = len(base.body or "")
    found: list[str] = []
    marker = secrets.token_hex(4)
    for word in wordlist:
        if word in _params_of(url):
            continue
        r = requester(_set_param(url, word, marker))
        # تغيّر ملحوظ في الطول، أو انعكاس اسم/قيمة المعامل = إشارة قبول.
        if abs(len(r.body or "") - base_len) >= threshold or marker in (r.body or ""):
            found.append(word)
    return found
