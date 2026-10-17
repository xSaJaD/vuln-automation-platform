"""اختبارات Phase 14 — المرونة: dead-letter، تسجيل الفشل، وإعادة المحاولة.

معيار القبول: فشل أثناء مهمة مهمة يُسجَّل بوضوح (الحالة failed)، لا "لا ثغرات".
"""

import pytest

from api.models.failed_task import FailedTask
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.recon import Host
from api.models.scan import ScanStatus
from api.services.resilience import record_failed_task
from workers.scan_logic import ScanTools, scan_hosts
from workers.strix_logic import StrixResult, run_strix_scan


def _program(db):
    p = Program(name="Demo", handle="demo")
    p.scope_assets = [ScopeAsset(kind=AssetKind.wildcard, identifier="*.example.com", in_scope=True)]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


# ── dead-letter ──

def test_record_failed_task(db_session):
    ft = record_failed_task(db_session, "scan.run_nuclei", [1, "example.com"], "Timeout")
    assert ft.id
    row = db_session.query(FailedTask).one()
    assert row.task_name == "scan.run_nuclei"
    assert "example.com" in row.args
    assert row.error == "Timeout"


# ── الفشل يُسجَّل كـ failed (لا "لا ثغرات") ──

def test_nuclei_crash_marks_scan_failed(db_session):
    p = _program(db_session)
    db_session.add(Host(program_id=p.id, hostname="a.example.com", in_scope=True, is_live=True))
    db_session.commit()

    def boom(_targets):
        raise RuntimeError("nuclei crashed")

    with pytest.raises(RuntimeError):
        scan_hosts(db_session, p, ScanTools(nuclei=boom))

    from api.models.scan import ScanRun

    sr = db_session.query(ScanRun).order_by(ScanRun.id.desc()).first()
    assert sr.status == ScanStatus.failed   # ليس "done" ولا نتائج فارغة


def test_strix_crash_marks_scan_failed(db_session):
    p = _program(db_session)

    def boom(_t, _i):
        raise RuntimeError("docker outage")

    with pytest.raises(RuntimeError):
        run_strix_scan(db_session, p, "app.example.com", boom)

    from api.models.scan import ScanRun

    sr = db_session.query(ScanRun).order_by(ScanRun.id.desc()).first()
    assert sr.status == ScanStatus.failed


def test_strix_timeout_is_failed_not_empty(db_session):
    """timeout (exit 124) => failed، لا يُفسَّر كـ لا ثغرات."""
    p = _program(db_session)
    sr, findings = run_strix_scan(db_session, p, "app.example.com", lambda t, i: StrixResult(exit_code=124))
    assert sr.status == ScanStatus.failed
    assert findings == []


# ── إعدادات إعادة المحاولة مطبّقة ──

def test_tasks_have_retry_policy():
    from workers.celery_app import celery_app

    for name in ("recon.run_full", "scan.run_nuclei", "strix.run", "pipeline.run_full"):
        assert celery_app.tasks[name].max_retries == 3
