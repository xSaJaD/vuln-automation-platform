"""اختبارات Phase 17 — كشف الحظر (WAF).

معيار القبول: محاكاة حظر WAF → النتيجة تُصنَّف inconclusive لا clean.
"""

from api.models.program import AssetKind, Program, ScopeAsset
from api.models.recon import Host
from api.models.scan import ScanStatus
from api.services.block_detection import looks_blocked, scan_outcome
from workers.scan_logic import ScanTools, scan_hosts


def test_looks_blocked_signals():
    assert looks_blocked(403) is True
    assert looks_blocked(429) is True
    assert looks_blocked(200, title="Attention Required! | Cloudflare") is True
    assert looks_blocked(200, body="please solve the captcha") is True
    assert looks_blocked(200, title="Welcome") is False


def test_scan_outcome_logic():
    assert scan_outcome(3, False) == "findings"
    assert scan_outcome(0, True) == "inconclusive"   # محظور بلا نتائج
    assert scan_outcome(0, False) == "clean"


def _program(db):
    p = Program(name="Demo", handle="demo")
    p.scope_assets = [ScopeAsset(kind=AssetKind.wildcard, identifier="*.example.com", in_scope=True)]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def test_waf_blocked_host_is_inconclusive(db_session):
    p = _program(db_session)
    db_session.add(
        Host(program_id=p.id, hostname="waf.example.com", in_scope=True, is_live=True,
             http_status=403, block_status="blocked")
    )
    db_session.commit()

    scan_run, findings = scan_hosts(db_session, p, ScanTools(nuclei=lambda t: []))
    assert findings == []
    assert scan_run.status == ScanStatus.done
    assert scan_run.outcome == "inconclusive"   # ليس clean


def test_clean_host_no_findings_is_clean(db_session):
    p = _program(db_session)
    db_session.add(
        Host(program_id=p.id, hostname="ok.example.com", in_scope=True, is_live=True,
             http_status=200, block_status="clean")
    )
    db_session.commit()

    scan_run, _ = scan_hosts(db_session, p, ScanTools(nuclei=lambda t: []))
    assert scan_run.outcome == "clean"


def test_host_with_findings_is_findings(db_session):
    p = _program(db_session)
    db_session.add(
        Host(program_id=p.id, hostname="app.example.com", in_scope=True, is_live=True,
             http_status=200, block_status="clean")
    )
    db_session.commit()

    def nuclei(_t):
        return [{"template-id": "x", "info": {"severity": "low"}, "host": "app.example.com",
                 "matched-at": "https://app.example.com/x"}]

    scan_run, findings = scan_hosts(db_session, p, ScanTools(nuclei=nuclei))
    assert len(findings) == 1
    assert scan_run.outcome == "findings"
