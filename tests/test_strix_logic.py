"""اختبارات منطق دمج Strix — معيار قبول Phase 5.

الأهم: Strix لا يُشغَّل على هدف خارج النطاق، ونتائجه تُنسَّق كـ findings
بـ source_tool='strix' و confirmed_by_strix=True وحالة needs_review.
"""

from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.scan import FindingStatus, ScanStatus
from workers.strix_logic import StrixResult, run_strix_scan


def _program(db):
    p = Program(name="Demo", handle="demo")
    p.scope_assets = [
        ScopeAsset(kind=AssetKind.wildcard, identifier="*.example.com", in_scope=True),
        ScopeAsset(kind=AssetKind.domain, identifier="example.com", in_scope=True),
    ]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _vuln(severity="high"):
    return {
        "type": "sqli",
        "title": "SQL Injection",
        "severity": severity,
        "url": "https://app.example.com/search?q=1",
        "poc": "' OR 1=1-- -",
        "description": "استغلال فعلي ناجح",
    }


def test_in_scope_target_runs_and_normalizes(db_session):
    p = _program(db_session)
    called = {}

    def runner(target, instruction):
        called["target"] = target
        return StrixResult(exit_code=1, vulnerabilities=[_vuln("critical")])

    scan_run, findings = run_strix_scan(db_session, p, "https://app.example.com", runner)

    assert called["target"] == "https://app.example.com"
    assert scan_run.status == ScanStatus.done
    assert len(findings) == 1

    f = findings[0]
    assert f.source_tool == "strix"
    assert f.confirmed_by_strix is True
    assert f.status == FindingStatus.needs_review     # مراجعة بشرية إلزامية
    assert f.severity == "critical"
    assert f.vuln_type == "sqli"
    assert f.host == "app.example.com"
    assert f.evidence == "' OR 1=1-- -"


def test_out_of_scope_target_never_runs_strix(db_session):
    p = _program(db_session)
    called = {"ran": False}

    def runner(target, instruction):
        called["ran"] = True
        return StrixResult(exit_code=0)

    scan_run, findings = run_strix_scan(db_session, p, "https://evil.com", runner)

    assert called["ran"] is False          # Strix لم يُشغَّل إطلاقًا
    assert findings == []
    assert scan_run.status == ScanStatus.failed

    # قرار الرفض مُسجَّل في audit_log
    deny = db_session.query(AuditLog).filter_by(decision="deny").count()
    assert deny >= 1


def test_timeout_marks_scan_failed(db_session):
    p = _program(db_session)
    runner = lambda t, i: StrixResult(exit_code=124)  # 124 = انتهت المهلة

    scan_run, findings = run_strix_scan(db_session, p, "https://app.example.com", runner)
    assert scan_run.status == ScanStatus.failed
    assert findings == []


def test_clean_result_no_findings(db_session):
    p = _program(db_session)
    runner = lambda t, i: StrixResult(exit_code=0, vulnerabilities=[])

    scan_run, findings = run_strix_scan(db_session, p, "example.com", runner)
    assert scan_run.status == ScanStatus.done
    assert findings == []
