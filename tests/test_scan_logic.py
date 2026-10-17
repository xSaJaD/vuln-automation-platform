"""اختبارات منطق الفحص (nuclei) — معيار قبول Phase 4.

الأهم: nuclei يُطبَّق على المضيفات الحيّة ضمن النطاق فقط، والنتائج منسّقة
بحقل source_tool='nuclei' وحالة needs_review.
"""

from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.recon import Host
from api.models.scan import FindingStatus
from workers.scan_logic import ScanTools, scan_hosts


def _program(db):
    p = Program(name="Demo", handle="demo")
    p.scope_assets = [ScopeAsset(kind=AssetKind.wildcard, identifier="*.example.com", in_scope=True)]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _host(db, program, name, in_scope=True, is_live=True):
    h = Host(program_id=program.id, hostname=name, in_scope=in_scope, is_live=is_live, source="subfinder")
    db.add(h)
    db.commit()
    return h


def _nuclei_result(host, severity="high", template="exposed-panel"):
    return {
        "template-id": template,
        "info": {"name": "Exposed Panel", "severity": severity},
        "host": host,
        "matched-at": f"https://{host}/admin",
        "matcher-name": "default-login",
    }


def test_only_in_scope_live_hosts_are_scanned(db_session):
    p = _program(db_session)
    _host(db_session, p, "api.example.com", in_scope=True, is_live=True)
    _host(db_session, p, "dead.example.com", in_scope=True, is_live=False)   # غير حيّ
    _host(db_session, p, "evil.com", in_scope=False, is_live=True)           # خارج النطاق

    scanned: dict = {}

    def spy_nuclei(targets):
        scanned["targets"] = list(targets)
        return [_nuclei_result(t) for t in targets]

    scan_run, findings = scan_hosts(db_session, p, ScanTools(nuclei=spy_nuclei))

    assert scanned["targets"] == ["api.example.com"]  # فقط الحيّ ضمن النطاق
    assert len(findings) == 1


def test_findings_are_normalized(db_session):
    p = _program(db_session)
    _host(db_session, p, "api.example.com")

    tools = ScanTools(nuclei=lambda t: [_nuclei_result("api.example.com", severity="critical")])
    _, findings = scan_hosts(db_session, p, tools)

    f = findings[0]
    assert f.source_tool == "nuclei"
    assert f.severity == "critical"
    assert f.vuln_type == "exposed-panel"
    assert f.endpoint == "https://api.example.com/admin"
    assert f.status == FindingStatus.needs_review   # لا تأكيد تلقائي
    assert f.confirmed_by_strix is False


def test_scope_rechecked_at_scan_time(db_session):
    """مضيف عُلِّم in_scope بالـ recon لكن النطاق تغيّر — يُحجب ويُسجَّل."""
    p = _program(db_session)
    # host خارج wildcard الحالي لكنه مُعلَّم in_scope (نطاق قديم)
    _host(db_session, p, "old.other.com", in_scope=True, is_live=True)

    scanned: dict = {}

    def spy_nuclei(targets):
        scanned["targets"] = list(targets)
        return []

    scan_hosts(db_session, p, ScanTools(nuclei=spy_nuclei))

    # nuclei لا يُستدعى أصلًا حين لا يوجد مضيف آمن — لم يُفحص رغم علم in_scope القديم
    assert scanned.get("targets", []) == []
    blocked = db_session.query(AuditLog).filter_by(action="scan_scope_block").count()
    assert blocked == 1


def test_no_live_hosts_yields_empty_scan(db_session):
    p = _program(db_session)
    scan_run, findings = scan_hosts(db_session, p, ScanTools(nuclei=lambda t: []))
    assert findings == []
    assert scan_run.tool == "nuclei"


def test_raw_results_saved(tmp_path, db_session):
    p = _program(db_session)
    _host(db_session, p, "api.example.com")
    tools = ScanTools(nuclei=lambda t: [_nuclei_result("api.example.com")])

    scan_run, _ = scan_hosts(db_session, p, tools, output_dir=str(tmp_path))

    raw_file = tmp_path / f"nuclei-{scan_run.id}" / "results.jsonl"
    assert raw_file.exists()
    assert "exposed-panel" in raw_file.read_text()
