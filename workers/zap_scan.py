"""دمج OWASP ZAP — فحص نشط عميق مُصادَق، بلا LLM.

يستخدم ZAP كخدمة daemon عبر REST API. يمرّر كوكي الجلسة (من تسجيل الدخول التلقائي)
إلى ZAP عبر قاعدة Replacer، فيزحف ويفحص وهو مُصادَق — فيكتشف ثغرات POST/حالة
(Command Injection, SQLi, …) أعمق من nuclei.

المنطق نقي وقابل للاختبار: عميل ZAP يُحقَن (كائن فيه request(path, params) -> dict).
"""

from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.program import Program
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import evaluate, host_of

# خطورة ZAP → خطورتنا.
_RISK_SEV = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


def _sev(risk: str | None) -> str:
    return _RISK_SEV.get((risk or "").strip().lower(), "info")


def alert_to_finding(scan_run_id: int, alert: dict) -> Finding:
    """يحوّل تنبيه ZAP إلى Finding موحّد."""
    name = alert.get("alert") or alert.get("name") or "unknown"
    url = alert.get("url") or ""
    parts: list[str] = []
    if alert.get("param"):
        parts.append(f"param={alert['param']}")
    if alert.get("evidence"):
        parts.append(f"evidence={alert['evidence']}")
    if alert.get("attack"):
        parts.append(f"attack={alert['attack']}")
    if alert.get("cweid") and str(alert["cweid"]) not in ("", "-1"):
        parts.append(f"CWE-{alert['cweid']}")
    return Finding(
        scan_run_id=scan_run_id,
        host=host_of(url) or url,
        endpoint=url or None,
        vuln_type=name,
        severity=_sev(alert.get("risk")),
        evidence="; ".join(parts) or None,
        source_tool="zap",
        status=FindingStatus.needs_review,
    )


def set_session_cookie(zap, cookie_header: str) -> None:
    """يجعل ZAP يضيف ترويسة Cookie لكل الطلبات (فحص مُصادَق)."""
    if not cookie_header:
        return
    zap.request(
        "/JSON/replacer/action/addRule/",
        {
            "description": "iqscan-auth",
            "enabled": "true",
            "matchType": "REQ_HEADER",
            "matchString": "Cookie",
            "matchRegex": "false",
            "replacement": cookie_header,
        },
    )


def _poll(zap, path: str, params: dict, *, interval: float = 3.0, max_wait: int = 1800) -> None:
    """ينتظر حتى تبلغ حالة ZAP (spider/ascan) 100% أو تنتهي المهلة."""
    waited = 0.0
    while True:
        st = zap.request(path, params)
        try:
            pct = int(st.get("status"))
        except (TypeError, ValueError):
            pct = 0
        if pct >= 100:
            return
        time.sleep(interval)
        waited += interval
        if waited >= max_wait:
            return


def _poll_ajax(zap, *, interval: float = 3.0, max_wait: int = 300) -> None:
    """ينتظر توقّف الـ AJAX Spider (حالته نصّية: running/stopped)."""
    waited = 0.0
    while waited < max_wait:
        st = zap.request("/JSON/ajaxSpider/view/status/", {})
        if str(st.get("status")) != "running":
            return
        time.sleep(interval)
        waited += interval


def run_zap_scan(
    db: Session,
    program: Program,
    seed: str,
    zap,
    *,
    cookie_header: str = "",
    actor: str = "zap",
    max_wait: int = 1800,
) -> tuple[ScanRun, list[Finding]]:
    """spider + active scan مُصادَق عبر ZAP، ثم تحويل التنبيهات إلى findings.

    كل تنبيه يُعاد التحقق من نطاق مضيفه قبل تخزينه (دفاع متعدد الطبقات).
    """
    scan_run = ScanRun(
        program_id=program.id, run_name=f"zap-{program.handle}", tool="zap", status=ScanStatus.running
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    try:
        set_session_cookie(zap, cookie_header)
        # ندخِل الرابط بشجرة مواقع ZAP أولًا (بالجلسة) — يمنع URL_NOT_FOUND في ascan
        # حتى لو رجع الزحف فاضيًا، ويتحقّق أن الهدف يُوصَل فعلًا.
        try:
            zap.request("/JSON/core/action/accessUrl/", {"url": seed, "followRedirects": "true"})
        except Exception:
            pass
        sp = zap.request("/JSON/spider/action/scan/", {"url": seed, "recurse": "true", "maxChildren": "0"})
        _poll(zap, "/JSON/spider/view/status/", {"scanId": sp.get("scan")}, max_wait=max_wait)
        # AJAX Spider — يلتقط روابط JavaScript والصفحات الديناميكية (يحسّن تغطية DOM).
        try:
            zap.request("/JSON/ajaxSpider/action/scan/", {"url": seed, "inScope": "false"})
            _poll_ajax(zap, max_wait=min(max_wait, 300))
        except Exception:
            pass
        asr = zap.request("/JSON/ascan/action/scan/", {"url": seed, "recurse": "true", "inScopeOnly": "false"})
        _poll(zap, "/JSON/ascan/view/status/", {"scanId": asr.get("scan")}, max_wait=max_wait)
        data = zap.request("/JSON/core/view/alerts/", {"baseurl": seed})
    except Exception:
        scan_run.status = ScanStatus.failed
        db.commit()
        raise

    rules = rules_for(program)
    findings: list[Finding] = []
    for alert in data.get("alerts", []):
        finding = alert_to_finding(scan_run.id, alert)
        decision = evaluate(finding.host, rules)
        if not decision.allowed:
            db.add(
                AuditLog(
                    action="zap_scope_block", target_value=finding.host, program_id=program.id,
                    decision="deny", reason=decision.reason, actor=actor,
                )
            )
            continue
        db.add(finding)
        findings.append(finding)

    scan_run.status = ScanStatus.done
    db.commit()
    return scan_run, findings


class ZapClient:
    """عميل REST بسيط لـ ZAP (stdlib)، يضيف apikey لكل طلب."""

    def __init__(self, base: str, apikey: str, timeout: int = 60):
        self.base = base.rstrip("/")
        self.apikey = apikey
        self.timeout = timeout

    def request(self, path: str, params: dict | None = None) -> dict:
        p = dict(params or {})
        p["apikey"] = self.apikey
        url = f"{self.base}{path}?{urllib.parse.urlencode(p)}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310
            body = r.read().decode("utf-8", "replace")
        return json.loads(body or "{}")
