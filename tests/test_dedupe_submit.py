"""اختبارات Phase 16 — فحص التكرار والإرسال.

معيار القبول: finding مطابق لتقرير سابق يُعلَّم likely_duplicate تلقائيًا.
والإرسال لا يتم إلا بموافقة صريحة + حالة مؤكّدة + مفاتيح مهيّأة.
"""

from types import SimpleNamespace

from api.models.program import Program
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.services.dedupe import flag_duplicates, is_duplicate
from workers.correlation_logic import correlate
from workers.hackerone import PriorReport, fetch_prior_reports


def _prior(title, asset, source="me"):
    return PriorReport(title=title, asset=asset, source=source)


# ── منطق التكرار ──

def test_is_duplicate_matches_host_and_type():
    f = SimpleNamespace(host="app.example.com", vuln_type="SQL Injection")
    priors = [_prior("SQL injection in login", "app.example.com")]
    assert is_duplicate(f, priors) is not None


def test_is_duplicate_no_match_different_host():
    f = SimpleNamespace(host="app.example.com", vuln_type="SQL Injection")
    priors = [_prior("SQL injection", "other.com")]
    assert is_duplicate(f, priors) is None


def test_h1_prior_mapping():
    raw = [{"title": "XSS", "asset": "shop.example.com", "source": "hacktivity"}]
    mapped = fetch_prior_reports("acme", fetcher=lambda h: raw)
    assert mapped[0].asset == "shop.example.com"
    assert mapped[0].source == "hacktivity"


# ── تعليم التكرار على بيانات حقيقية ──

def _seed_correlated(db, status=FindingStatus.needs_review):
    p = Program(name="Acme", handle="acme")
    db.add(p)
    db.commit()
    db.refresh(p)
    sr = ScanRun(program_id=p.id, run_name="n", tool="nuclei", status=ScanStatus.done)
    db.add(sr)
    db.commit()
    db.refresh(sr)
    db.add(
        Finding(scan_run_id=sr.id, host="app.acme.com", endpoint="https://app.acme.com/x",
                vuln_type="SQL Injection", severity="high", source_tool="nuclei")
    )
    db.commit()
    cf = correlate(db, p)[0]
    cf.status = status
    db.commit()
    db.refresh(cf)
    return p, cf


def test_flag_duplicates_sets_flag(db_session):
    p, cf = _seed_correlated(db_session)
    priors = [_prior("SQL injection found", "app.acme.com")]

    flagged = flag_duplicates(db_session, p, priors)
    assert flagged == 1
    db_session.refresh(cf)
    assert cf.likely_duplicate is True
    assert "app.acme.com" not in (cf.duplicate_ref or "")  # المرجع هو عنوان التقرير والمصدر
    assert cf.duplicate_ref.startswith("me:")


# ── الإرسال محميّ ──

def test_submit_requires_confirmed_status(client, db_session):
    _p, cf = _seed_correlated(db_session, status=FindingStatus.needs_review)
    r = client.post(f"/correlated/{cf.id}/submit", json={"confirm": True})
    assert r.status_code == 409


def test_submit_requires_explicit_confirm(client, db_session):
    _p, cf = _seed_correlated(db_session, status=FindingStatus.confirmed)
    r = client.post(f"/correlated/{cf.id}/submit", json={"confirm": False})
    assert r.status_code == 400


def test_submit_requires_credentials(client, db_session, monkeypatch):
    from api.config import settings

    monkeypatch.setattr(settings, "hackerone_api_username", "")
    monkeypatch.setattr(settings, "hackerone_api_token", "")
    _p, cf = _seed_correlated(db_session, status=FindingStatus.confirmed)
    r = client.post(f"/correlated/{cf.id}/submit", json={"confirm": True})
    assert r.status_code == 503


def test_submit_success_marks_reported(client, db_session, monkeypatch):
    from api.config import settings
    from workers import hackerone

    monkeypatch.setattr(settings, "hackerone_api_username", "u")
    monkeypatch.setattr(settings, "hackerone_api_token", "t")
    monkeypatch.setattr(
        hackerone, "submit_report",
        lambda *a, **k: {"id": "12345", "url": "https://hackerone.com/reports/12345"},
    )

    _p, cf = _seed_correlated(db_session, status=FindingStatus.confirmed)
    r = client.post(f"/correlated/{cf.id}/submit", json={"confirm": True})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "reported"
    assert body["submitted_ref"] == "https://hackerone.com/reports/12345"

    from api.models.audit import AuditLog

    assert db_session.query(AuditLog).filter_by(action="report_submit").count() == 1
