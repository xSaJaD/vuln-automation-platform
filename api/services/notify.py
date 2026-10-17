"""تنبيهات عبر Webhook (Slack/Telegram/عام) + منطق مراقبة العمّال.

المُرسِل (sender) يُحقَن حتى يمكن اختباره بلا شبكة. التنبيه الفعلي يرسل JSON
إلى NOTIFY_WEBHOOK_URL. التنبيهات تخضع لحدّ خطورة أدنى (NOTIFY_MIN_SEVERITY).
"""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from api.config import settings

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _field(f, name):
    return f.get(name) if isinstance(f, dict) else getattr(f, name, None)


@dataclass
class Notifier:
    sender: Callable[[str], None]
    min_severity: str = "high"

    def _passes(self, severity: str | None) -> bool:
        return _SEV_ORDER.get((severity or "").lower(), 0) >= _SEV_ORDER.get(self.min_severity, 3)

    def send(self, message: str) -> None:
        self.sender(message)

    def finding(self, f) -> bool:
        sev = _field(f, "severity")
        if not self._passes(sev):
            return False
        self.send(
            f"🔴 [{str(sev).upper()}] {_field(f, 'vuln_type')} على {_field(f, 'host')} "
            f"(CVSS {_field(f, 'cvss_score')})"
        )
        return True

    def scan_done(self, program_handle: str, count: int) -> None:
        self.send(f"✅ انتهى فحص {program_handle}: {count} نتيجة")

    def task_failed(self, name: str, reason: str) -> None:
        self.send(f"⚠ فشلت مهمة {name}: {reason}")


def notify_findings(notifier: Notifier, findings) -> int:
    """يُنبّه عن النتائج التي تتجاوز حدّ الخطورة. يرجّع عددها."""
    return sum(1 for f in findings if notifier.finding(f))


def evaluate_worker_health(ping_result, notifier: Notifier | None) -> int:
    """يرجّع عدد العمّال الأحياء؛ يُنبّه إن لم يوجد أي worker نشط."""
    alive = len(ping_result) if ping_result else 0
    if alive == 0 and notifier is not None:
        notifier.send("⛔ لا يوجد أي worker نشط — تحقّق من خدمة الفحص")
    return alive


def _webhook_sender(url: str) -> Callable[[str], None]:
    def send(message: str) -> None:
        data = json.dumps({"text": message}, ensure_ascii=False).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=10)  # noqa: S310
        except Exception:
            pass  # التنبيه best-effort — لا يُفشل الفحص

    return send


def get_notifier() -> Notifier | None:
    url = settings.notify_webhook_url
    if not url:
        return None
    return Notifier(sender=_webhook_sender(url), min_severity=settings.notify_min_severity)
