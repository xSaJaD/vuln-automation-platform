"""اختبارات الدمج (Normalize + Correlate) — معيار قبول Phase 6.

الأهم: نتيجتان متشابهتان من nuclei و Strix تندمجان بسجل واحد مع
confirmed_by_strix=True.
"""

from api.models.program import Program
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from workers.correlation_logic import correlate, correlation_key


def _program(db):
    p = Program(name="Demo", handle="demo")
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _scan_run(db, program, tool):
    sr = ScanRun(program_id=program.id, run_name=f"{tool}-run", tool=tool, status=ScanStatus.done)
    db.add(sr)
    db.commit()
    db.refresh(sr)
    return sr


def _finding(db, scan_run, *, source, severity="medium", confirmed=False):
    f = Finding(
        scan_run_id=scan_run.id,
        host="app.example.com",
        endpoint="https://app.example.com/search",
        vuln_type="sqli",
        severity=severity,
        source_tool=source,
        confirmed_by_strix=confirmed,
        status=FindingStatus.needs_review,
    )
    db.add(f)
    db.commit()
    return f


def test_nuclei_and_strix_merge_into_one(db_session):
    p = _program(db_session)
    _finding(db_session, _scan_run(db_session, p, "nuclei"), source="nuclei", severity="medium")
    _finding(
        db_session, _scan_run(db_session, p, "strix"),
        source="strix", severity="high", confirmed=True,
    )

    result = correlate(db_session, p)

    assert len(result) == 1                       # سجل موحّد واحد
    cf = result[0]
    assert cf.sources == "nuclei,strix"
    assert cf.confirmed_by_strix is True          # Strix أكّدها
    assert cf.severity == "high"                  # أعلى خطورة
    assert cf.finding_count == 2


def test_different_findings_stay_separate(db_session):
    p = _program(db_session)
    sr = _scan_run(db_session, p, "nuclei")
    _finding(db_session, sr, source="nuclei")
    # finding مختلف (نوع ثغرة آخر)
    other = Finding(
        scan_run_id=sr.id, host="app.example.com",
        endpoint="https://app.example.com/login", vuln_type="xss",
        severity="low", source_tool="nuclei",
    )
    db_session.add(other)
    db_session.commit()

    result = correlate(db_session, p)
    assert len(result) == 2


def test_correlation_is_idempotent(db_session):
    p = _program(db_session)
    _finding(db_session, _scan_run(db_session, p, "nuclei"), source="nuclei")

    correlate(db_session, p)
    second = correlate(db_session, p)

    from api.models.correlation import CorrelatedFinding

    assert db_session.query(CorrelatedFinding).count() == 1
    assert len(second) == 1


def test_only_strix_source_is_confirmed(db_session):
    p = _program(db_session)
    # Strix بدون علم confirmed صريح — المصدر نفسه يكفي للتأكيد
    _finding(db_session, _scan_run(db_session, p, "strix"), source="strix", confirmed=False)
    cf = correlate(db_session, p)[0]
    assert cf.confirmed_by_strix is True


def test_correlation_key_normalizes():
    k1 = correlation_key("APP.Example.com", "https://APP.example.com/x", "SQLi")
    k2 = correlation_key("app.example.com", "https://app.example.com/x", "sqli")
    assert k1 == k2
