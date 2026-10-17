"""اختبارات توليد التقارير — معيار قبول Phase 8.

الأهم: التقرير مسودة تحمل تنبيه "لا إرسال آلي"، ولا يُولَّد إلا لـ finding مؤكَّد.
"""

from api.models.correlation import CorrelatedFinding
from api.models.program import Program
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.services.report_generator import render_report
from workers.correlation_logic import correlate


def _confirmed_finding(db, status=FindingStatus.confirmed):
    p = Program(name="Acme", handle="acme")
    db.add(p)
    db.commit()
    db.refresh(p)
    sr = ScanRun(program_id=p.id, run_name="n", tool="strix", status=ScanStatus.done)
    db.add(sr)
    db.commit()
    db.refresh(sr)
    db.add(
        Finding(
            scan_run_id=sr.id, host="app.acme.com",
            endpoint="https://app.acme.com/search", vuln_type="sqli",
            severity="high", source_tool="strix", confirmed_by_strix=True,
            evidence="' OR 1=1-- -",
        )
    )
    db.commit()
    cf = correlate(db, p)[0]
    cf.status = status
    db.commit()
    db.refresh(cf)
    return p, cf


# ── اختبار المولّد النقي ──

def test_render_contains_key_sections(db_session):
    program, cf = _confirmed_finding(db_session)
    md = render_report(cf, program)

    assert "مسودة" in md
    assert "لا تُرسَل آليًا إلى HackerOne" in md     # قاعدة عدم الإرسال الآلي
    assert "SQL Injection" in md
    assert "CVSS" in md
    assert "' OR 1=1-- -" in md                      # الـ PoC
    assert "التوصية بالإصلاح" in md
    assert "app.acme.com" in md


# ── اختبار الـ API ──

def test_report_generated_for_confirmed(client, db_session):
    _program, cf = _confirmed_finding(db_session)
    r = client.post(f"/correlated/{cf.id}/report", params={"save": "false"})
    assert r.status_code == 200
    body = r.json()
    assert body["draft"] is True
    assert "SQL Injection" in body["markdown"]


def test_report_blocked_for_unreviewed(client, db_session):
    _program, cf = _confirmed_finding(db_session, status=FindingStatus.needs_review)
    r = client.post(f"/correlated/{cf.id}/report", params={"save": "false"})
    assert r.status_code == 409   # لا تقرير قبل التأكيد


def test_report_saved_to_disk(tmp_path, client, db_session, monkeypatch):
    from api.config import settings

    monkeypatch.setattr(settings, "reports_out_dir", str(tmp_path))
    _program, cf = _confirmed_finding(db_session)

    r = client.post(f"/correlated/{cf.id}/report", params={"save": "true"})
    assert r.status_code == 200
    saved = r.json()["saved_to"]
    assert saved and (tmp_path / "acme" / f"finding-{cf.id}.md").exists()
