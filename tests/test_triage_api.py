"""اختبار triage عبر الـ API — معيار قبول Phase 7."""

from api.models.audit import AuditLog
from api.models.program import Program
from api.models.scan import Finding, ScanRun, ScanStatus
from workers.correlation_logic import correlate


def _seed_correlated(db):
    p = Program(name="D", handle="d")
    db.add(p)
    db.commit()
    db.refresh(p)
    sr = ScanRun(program_id=p.id, run_name="n", tool="nuclei", status=ScanStatus.done)
    db.add(sr)
    db.commit()
    db.refresh(sr)
    db.add(
        Finding(
            scan_run_id=sr.id, host="a.example.com",
            endpoint="https://a.example.com/x", vuln_type="sqli",
            severity="high", source_tool="nuclei",
        )
    )
    db.commit()
    return correlate(db, p)[0]


def test_auto_cvss_set_on_correlation(client, db_session):
    cf = _seed_correlated(db_session)
    assert cf.cvss_score and cf.cvss_score >= 7.0
    assert cf.cvss_manual is False


def test_triage_status_transition(client, db_session):
    cf = _seed_correlated(db_session)

    r = client.post(f"/correlated/{cf.id}/triage", json={"status": "confirmed", "actor": "sajo"})
    assert r.status_code == 200
    assert r.json()["status"] == "confirmed"

    # انتقال غير مسموح
    bad = client.post(f"/correlated/{cf.id}/triage", json={"status": "resolved"})
    assert bad.status_code == 422


def test_manual_cvss_override(client, db_session):
    cf = _seed_correlated(db_session)

    r = client.post(
        f"/correlated/{cf.id}/triage",
        json={"cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["cvss_score"] == 9.8
    assert body["cvss_manual"] is True


def test_triage_is_audited(client, db_session):
    cf = _seed_correlated(db_session)
    client.post(f"/correlated/{cf.id}/triage", json={"status": "confirmed", "actor": "sajo"})

    rows = db_session.query(AuditLog).filter_by(action="triage").all()
    assert len(rows) >= 1
    assert rows[-1].actor == "sajo"
