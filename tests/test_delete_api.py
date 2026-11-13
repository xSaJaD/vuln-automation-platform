"""اختبارات حذف النتائج الموحّدة وأصول النطاق (تعديلات اللوحة)."""

from api.models.audit import AuditLog
from api.models.correlation import CorrelatedFinding
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
    return p, correlate(db, p)[0]


def test_delete_correlated_finding(client, db_session):
    _p, cf = _seed_correlated(db_session)
    fid = cf.id

    r = client.delete(f"/correlated/{fid}")
    assert r.status_code == 204
    assert db_session.get(CorrelatedFinding, fid) is None

    # الحذف مُسجَّل في سجل التدقيق.
    rows = db_session.query(AuditLog).filter_by(action="delete_finding").all()
    assert len(rows) == 1

    # حذف نتيجة غير موجودة => 404
    assert client.delete(f"/correlated/{fid}").status_code == 404


def test_delete_scope_asset(client):
    pid = client.post("/programs", json={"name": "Acme", "handle": "acme"}).json()["id"]
    aid = client.post(
        f"/programs/{pid}/scope",
        json={"kind": "domain", "identifier": "acme.com", "in_scope": True},
    ).json()["id"]

    assert client.delete(f"/programs/{pid}/scope/{aid}").status_code == 204
    assert client.get(f"/programs/{pid}/scope").json() == []

    # أصل غير موجود => 404
    assert client.delete(f"/programs/{pid}/scope/{aid}").status_code == 404


def test_delete_scope_wrong_program(client):
    p1 = client.post("/programs", json={"name": "A", "handle": "a"}).json()["id"]
    p2 = client.post("/programs", json={"name": "B", "handle": "b"}).json()["id"]
    aid = client.post(
        f"/programs/{p1}/scope",
        json={"kind": "domain", "identifier": "a.com", "in_scope": True},
    ).json()["id"]

    # لا يُحذف أصل برنامج عبر برنامج آخر.
    assert client.delete(f"/programs/{p2}/scope/{aid}").status_code == 404
