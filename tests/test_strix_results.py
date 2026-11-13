"""اختبارات: حذف كل النتائج + وضعا Strix (جديد / أكمل من السابق) + فحص LLM."""

import pytest

from api.config import settings
from api.models.correlation import CorrelatedFinding
from api.models.program import Program
from api.models.scan import Finding, ScanRun, ScanStatus
from workers.correlation_logic import correlate


@pytest.fixture
def llm_key():
    old = settings.llm_api_key
    settings.llm_api_key = "test-key"
    yield
    settings.llm_api_key = old


def _seed_results(db):
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
            scan_run_id=sr.id, host="dvwa", endpoint="http://dvwa/x",
            vuln_type="sqli", severity="high", source_tool="nuclei",
        )
    )
    db.commit()
    correlate(db, p)
    return p


def test_delete_all_results(client, db_session):
    p = _seed_results(db_session)
    assert db_session.query(CorrelatedFinding).count() >= 1

    r = client.delete(f"/programs/{p.id}/results")
    assert r.status_code == 204
    assert db_session.query(CorrelatedFinding).count() == 0
    assert db_session.query(Finding).count() == 0
    assert db_session.query(ScanRun).count() == 0


def test_strix_requires_llm_key(client):
    pid = client.post("/programs", json={"name": "A", "handle": "a"}).json()["id"]
    client.post(f"/programs/{pid}/scope", json={"kind": "domain", "identifier": "dvwa", "in_scope": True})
    # بلا LLM key => 400 واضح بدل فشل صامت.
    r = client.post(f"/programs/{pid}/strix", json={"target": "http://dvwa/"})
    assert r.status_code == 400


def test_strix_continue_out_of_scope(client, llm_key):
    pid = client.post("/programs", json={"name": "A", "handle": "a"}).json()["id"]
    client.post(f"/programs/{pid}/scope", json={"kind": "domain", "identifier": "dvwa", "in_scope": True})
    r = client.post(f"/programs/{pid}/strix/continue", json={"target": "http://evil.com/"})
    assert r.status_code == 403


def test_strix_continue_in_scope_builds_and_enqueues(client, llm_key):
    pid = client.post("/programs", json={"name": "A", "handle": "a"}).json()["id"]
    client.post(f"/programs/{pid}/scope", json={"kind": "domain", "identifier": "dvwa", "in_scope": True})
    # ضمن النطاق + LLM مضبوط => يتجاوز الفحوص ويحاول الجدولة (الطابور غير متاح => 503).
    r = client.post(f"/programs/{pid}/strix/continue", json={"target": "http://dvwa/", "instruction": "ركّز على XSS"})
    assert r.status_code in (503, 200)
