"""فحص مُصادَق (Authenticated DAST) — بلا Strix.

النظام يسجّل دخولًا نموذجيًا (form login) إلى الهدف المصرّح به، يجلب كوكي الجلسة
(ويكشط CSRF token إن لزم)، ثم يشغّل nuclei بوضع fuzzing (-dast) على الروابط ذات
البارامترات لاكتشاف XSS/SQLi التفاعلية خلف تسجيل الدخول.

الضمانات:
  • كل هدف يمر عبر Scope Gatekeeper (re-check وقت الفحص) ويُسجَّل.
  • بيانات الدخول عابرة (لا تُخزَّن) وتُستخدم فقط ضد هدف مصرّح به تملكه.
  • النتائج تدخل بحالة needs_review — لا تأكيد تلقائي ولا إرسال.

منطق تسجيل الدخول نقي وقابل للاختبار: عميل HTTP يُحقَن (client فيه get/post/cookies).
"""

from __future__ import annotations

import http.cookiejar
import re
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.program import Program
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import evaluate, host_of


@dataclass
class LoginConfig:
    """إعداد تسجيل دخول نموذجي (form login) عام قابل للتكيّف مع DVWA وغيره."""

    url: str | None = None
    username: str | None = None
    password: str | None = None
    username_field: str = "username"
    password_field: str = "password"
    token_field: str | None = None            # حقل CSRF مخفي يُكشط من صفحة الدخول
    extra_fields: dict[str, str] = field(default_factory=dict)   # مثل {"Login":"Login"}
    extra_cookies: dict[str, str] = field(default_factory=dict)  # مثل {"security":"low"}


def extract_token(html: str, name: str) -> str | None:
    """يكشط قيمة حقل input مخفي (مثل DVWA user_token) من HTML صفحة الدخول."""
    if not html or not name:
        return None
    patterns = [
        r'name=["\']' + re.escape(name) + r'["\'][^>]*value=["\']([^"\']*)["\']',
        r'value=["\']([^"\']*)["\'][^>]*name=["\']' + re.escape(name) + r'["\']',
    ]
    for pat in patterns:
        m = re.search(pat, html, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def authenticate(client, cfg: LoginConfig) -> dict[str, str]:
    """يسجّل دخولًا نموذجيًا ويرجّع قاموس الكوكيز (جلسة + أي كوكيز إضافية).

    client: كائن فيه get(url)->resp(.text) و post(url,data)->resp و cookies()->dict.
    """
    if cfg.url and cfg.username is not None:
        page = client.get(cfg.url).text
        data: dict[str, str] = {
            cfg.username_field: cfg.username or "",
            cfg.password_field: cfg.password or "",
        }
        data.update(cfg.extra_fields)
        if cfg.token_field:
            tok = extract_token(page, cfg.token_field)
            if tok is not None:
                data[cfg.token_field] = tok
        client.post(cfg.url, data)
    cookies = dict(client.cookies())
    cookies.update(cfg.extra_cookies)   # security=low يتغلّب
    return cookies


def cookie_header(cookies: dict[str, str]) -> str:
    """يبني ترويسة Cookie من قاموس."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items() if k)


class UrllibClient:
    """عميل HTTP بسيط بلا اعتماد خارجي (stdlib) — يحفظ الكوكيز عبر الطلبات."""

    def __init__(self, timeout: int = 30):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.timeout = timeout

    class _Resp:
        def __init__(self, text: str, url: str = ""):
            self.text = text
            self.url = url

    def get(self, url: str) -> UrllibClient._Resp:
        req = urllib.request.Request(url, headers={"User-Agent": "IQScan-AuthScan"})
        with self.opener.open(req, timeout=self.timeout) as r:  # noqa: S310 (هدف مصرّح به)
            return self._Resp(r.read().decode("utf-8", "replace"), r.geturl())

    def post(self, url: str, data: dict[str, str]) -> UrllibClient._Resp:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body, headers={"User-Agent": "IQScan-AuthScan"})
        with self.opener.open(req, timeout=self.timeout) as r:  # noqa: S310
            return self._Resp(r.read().decode("utf-8", "replace"), r.geturl())

    def cookies(self) -> dict[str, str]:
        return {c.name: c.value for c in self.jar}


def _finding_from_nuclei_dast(scan_run_id: int, item: dict) -> Finding:
    info = item.get("info") or {}
    host = item.get("host") or ""
    matched = item.get("matched-at") or item.get("matched_at") or host
    parts: list[str] = []
    if item.get("matcher-name"):
        parts.append(f"matcher={item['matcher-name']}")
    if item.get("extracted-results"):
        parts.append(f"extracted={item['extracted-results']}")
    # بوضع DAST يفيد تمييز البارامتر المُستغَل إن توفّر.
    fuzz = item.get("fuzzing-parameter") or (item.get("fuzz_metadata") or {}).get("parameter")
    if fuzz:
        parts.append(f"param={fuzz}")
    return Finding(
        scan_run_id=scan_run_id,
        host=host_of(host or matched) or (host or matched),
        endpoint=matched or None,
        vuln_type=item.get("template-id") or info.get("name") or "unknown",
        severity=(info.get("severity") or "info").lower(),
        evidence="; ".join(parts) or None,
        source_tool="nuclei-dast",
        status=FindingStatus.needs_review,
    )


def run_authscan(
    db: Session,
    program: Program,
    targets: list[str],
    nuclei_dast: Callable[[list[str]], list[dict]],
    *,
    actor: str = "authscan",
) -> tuple[ScanRun, list[Finding]]:
    """يفحص روابط مصرّحًا بها بوضع DAST. nuclei_dast تُحقَن (الكوكي/الوضع جاهز فيها)."""
    scan_run = ScanRun(
        program_id=program.id,
        run_name=f"dast-{program.handle}",
        tool="nuclei-dast",
        status=ScanStatus.running,
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    # إعادة التحقق من النطاق لكل هدف (الطبقة الدفاعية وقت الفحص).
    rules = rules_for(program)
    safe: list[str] = []
    for tgt in targets:
        host = host_of(tgt) or tgt
        decision = evaluate(host, rules)
        if decision.allowed:
            safe.append(tgt)
        else:
            db.add(
                AuditLog(
                    action="authscan_scope_block",
                    target_value=tgt,
                    program_id=program.id,
                    decision="deny",
                    reason=decision.reason,
                    actor=actor,
                )
            )
    db.commit()

    try:
        raw = nuclei_dast(safe) if safe else []
    except Exception:
        scan_run.status = ScanStatus.failed
        db.commit()
        raise

    findings: list[Finding] = []
    for item in raw:
        finding = _finding_from_nuclei_dast(scan_run.id, item)
        db.add(finding)
        findings.append(finding)

    scan_run.status = ScanStatus.done
    db.commit()
    return scan_run, findings
