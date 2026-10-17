"""اختبارات Phase 13 — التنبيهات والمراقبة والسجلّات."""

import json
import logging
from types import SimpleNamespace

from api.logging_config import JsonFormatter
from api.services.notify import Notifier, evaluate_worker_health, notify_findings


def _collector():
    out = []
    return out, Notifier(sender=out.append, min_severity="high")


def _finding(sev):
    return SimpleNamespace(severity=sev, vuln_type="SQLi", host="app.example.com", cvss_score=9.1)


# ── عتبة الخطورة ──

def test_notifies_critical_and_high_only():
    out, n = _collector()
    assert n.finding(_finding("critical")) is True
    assert n.finding(_finding("high")) is True
    assert n.finding(_finding("medium")) is False
    assert n.finding(_finding("low")) is False
    assert len(out) == 2  # الحرجة والعالية فقط


def test_notify_findings_counts():
    out, n = _collector()
    sent = notify_findings(n, [_finding("critical"), _finding("low"), _finding("high")])
    assert sent == 2
    assert "app.example.com" in out[0]


def test_scan_done_and_task_failed():
    out, n = _collector()
    n.scan_done("acme", 5)
    n.task_failed("scan.run_nuclei", "timeout")
    assert any("acme" in m for m in out)
    assert any("فشلت" in m for m in out)


# ── مراقبة العمّال (معيار القبول) ──

def test_alert_when_no_workers():
    out, n = _collector()
    alive = evaluate_worker_health({}, n)   # لا عمّال
    assert alive == 0
    assert len(out) == 1 and "worker" in out[0]


def test_no_alert_when_workers_present():
    out, n = _collector()
    alive = evaluate_worker_health({"celery@host1": {"ok": "pong"}}, n)
    assert alive == 1
    assert out == []   # لا تنبيه


# ── سجلّات JSON ──

def test_json_log_format():
    rec = logging.LogRecord("t", logging.INFO, __file__, 1, "رسالة اختبار", None, None)
    line = JsonFormatter().format(rec)
    data = json.loads(line)   # لازم JSON صالح
    assert data["level"] == "INFO"
    assert data["msg"] == "رسالة اختبار"
    assert "ts" in data
