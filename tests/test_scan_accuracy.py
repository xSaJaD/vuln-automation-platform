"""اختبارات دقة الفحص: الفشل ليس "نظيف"، التطبيع، الدمج، التحقق، المنافذ، wildcard DNS."""

import subprocess
from types import SimpleNamespace

import pytest

from api.models.audit import AuditLog
from api.models.correlation import CorrelatedFinding
from api.models.program import AssetKind, Program, ScopeAsset
from api.models.recon import Host
from api.models.scan import Finding, ScanRun, ScanStatus
from api.services.block_detection import blocked_by_ratio, looks_blocked
from api.services.dedupe import is_duplicate
from api.services.vuln_class import classify, normalize_endpoint
from workers import tools
from workers.correlation_logic import correlate, correlation_key
from workers.recon_logic import ReconTools, run_full_recon
from workers.scan_logic import ScanTools, scan_hosts
from workers.strix_cli import _extract
from workers.strix_logic import StrixResult, run_strix_scan
from workers.verify_logic import verify_findings


def _program(db, rate=None):
    p = Program(name="Demo", handle="demo", rate_limit_per_min=rate)
    p.scope_assets = [
        ScopeAsset(kind=AssetKind.wildcard, identifier="*.example.com", in_scope=True),
        ScopeAsset(kind=AssetKind.domain, identifier="example.com", in_scope=True),
    ]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _host(db, program, name, **kw):
    h = Host(program_id=program.id, hostname=name, in_scope=True, is_live=True, **kw)
    db.add(h)
    db.commit()
    return h


def _nuclei_item(url, template="exposed-panel", cwe=None, name="Exposed Panel"):
    info = {"name": name, "severity": "high"}
    if cwe:
        info["classification"] = {"cwe-id": [cwe]}
    return {
        "template-id": template,
        "info": info,
        "host": url,
        "matched-at": url,
        "request": "GET / HTTP/1.1",
        "response": "HTTP/1.1 200 OK",
        "curl-command": f"curl -X GET {url}",
    }


# ── الأدوات: الفشل يُرفع ولا يُقرأ كـ "لا نتائج" ──

def _fake_run(returncode, stdout="", stderr="boom"):
    def run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    return run


def test_nuclei_failure_raises_not_empty(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda b: "/bin/" + b)
    monkeypatch.setattr(tools.subprocess, "run", _fake_run(2))
    with pytest.raises(tools.ToolError):
        tools.run_nuclei(["https://a.example.com"])


def test_nuclei_success_with_no_findings_is_empty(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda b: "/bin/" + b)
    monkeypatch.setattr(tools.subprocess, "run", _fake_run(0))
    assert tools.run_nuclei(["https://a.example.com"]) == []


def test_nuclei_command_applies_program_rate():
    assert "-rate-limit-minute" in tools.nuclei_command(rate_per_min=30)
    assert "30" in tools.nuclei_command(rate_per_min=30)
    assert "-rate-limit-minute" not in tools.nuclei_command()
    with pytest.raises(ValueError):
        tools.nuclei_command(template_ids=["-evil"])


# ── الفحص ──

def test_scan_failure_recorded_with_error(db_session):
    p = _program(db_session)
    _host(db_session, p, "api.example.com")

    def broken(targets):
        raise tools.ToolError("nuclei فشل")

    with pytest.raises(tools.ToolError):
        scan_hosts(db_session, p, ScanTools(nuclei=broken))
    sr = db_session.query(ScanRun).one()
    assert sr.status == ScanStatus.failed
    assert sr.outcome is None            # ليس clean
    assert "nuclei" in sr.error


def test_scan_uses_all_live_urls_including_ports(db_session):
    p = _program(db_session)
    _host(
        db_session, p, "api.example.com",
        urls="https://api.example.com\nhttp://api.example.com:8080\nhttps://evil.com",
    )
    seen = {}

    def spy(targets):
        seen["t"] = targets
        return []

    scan_hosts(db_session, p, ScanTools(nuclei=spy))
    assert seen["t"] == ["https://api.example.com", "http://api.example.com:8080"]


def test_scan_stores_full_evidence_and_class(db_session):
    p = _program(db_session)
    _host(db_session, p, "api.example.com")
    item = _nuclei_item("https://api.example.com/q?id=1", template="generic-sqli", cwe="CWE-89")
    _, findings = scan_hosts(db_session, p, ScanTools(nuclei=lambda t: [item]))
    f = findings[0]
    assert f.vuln_class == "sqli" and f.cwe == "CWE-89"
    assert f.request and f.response and f.curl_command.startswith("curl")


def test_scan_drops_results_on_unrequested_hosts(db_session):
    p = _program(db_session)
    _host(db_session, p, "api.example.com")
    item = _nuclei_item("https://third-party.com/x")
    _, findings = scan_hosts(db_session, p, ScanTools(nuclei=lambda t: [item]))
    assert findings == []
    assert db_session.query(AuditLog).filter_by(action="scan_result_dropped").count() == 1


def test_blocked_host_without_findings_is_listed(db_session):
    p = _program(db_session)
    _host(db_session, p, "a.example.com", block_status="blocked")
    _host(db_session, p, "b.example.com", block_status="clean")
    item = _nuclei_item("https://b.example.com/admin")
    sr, _ = scan_hosts(db_session, p, ScanTools(nuclei=lambda t: [item]))
    assert sr.outcome == "findings"
    assert sr.blocked_hosts == "a.example.com"   # نتيجته غير حاسمة رغم نتائج غيره


def test_block_detection_401_is_not_waf():
    assert looks_blocked(401) is False
    assert looks_blocked(403) is True
    assert blocked_by_ratio([403, 403, 429, 200, 403]) is True
    assert blocked_by_ratio([200, 200, 200, 403, 200]) is False
    assert blocked_by_ratio([403, 403]) is False   # عيّنة غير كافية


# ── Strix ──

def test_strix_nonzero_exit_is_failed(db_session):
    p = _program(db_session)
    sr, _ = run_strix_scan(
        db_session, p, "app.example.com", lambda t, i: StrixResult(exit_code=1)
    )
    assert sr.status == ScanStatus.failed
    assert sr.outcome is None
    assert "1" in sr.error


def test_strix_out_of_scope_result_dropped(db_session):
    p = _program(db_session)
    vulns = [
        {"title": "SQL Injection", "severity": "high", "url": "https://app.example.com/a"},
        {"title": "XSS", "severity": "low", "url": "https://other.org/b"},
    ]
    _, findings = run_strix_scan(
        db_session, p, "app.example.com", lambda t, i: StrixResult(0, vulns)
    )
    assert [f.host for f in findings] == ["app.example.com"]
    assert findings[0].vuln_class == "sqli"


def test_strix_parser_ignores_non_vuln_json():
    assert _extract({"title": "run config", "model": "x"}) == []
    assert _extract([{"title": "state"}, {"title": "XSS", "severity": "High"}]) == [
        {"title": "XSS", "severity": "High"}
    ]


# ── التطبيع والدمج ──

def test_classify():
    assert classify("generic-sqli", ["CWE-89"]) == ("sqli", "CWE-89")
    assert classify("SQL Injection")[0] == "sqli"
    assert classify("Reflected Cross-Site Scripting")[0] == "xss"
    assert classify("selfie-upload")[0] == "selfie-upload"   # lfi لا يطابق داخل كلمة
    assert classify("open-source-license")[0] == "open-source-license"
    assert classify("CVE-2021-44228")[0] == "cve-2021-44228"


def test_normalize_endpoint_drops_query_values():
    a = normalize_endpoint("https://App.example.com/x/?id=1&b=2")
    b = normalize_endpoint("http://app.example.com/x?b=9&id=7")
    assert a == b == "app.example.com/x?b&id"
    assert normalize_endpoint("https://app.example.com:8443/x") == "app.example.com:8443/x"


def test_nuclei_and_strix_merge_despite_different_names(db_session):
    p = _program(db_session)
    sr = ScanRun(program_id=p.id, run_name="r", tool="x", status=ScanStatus.done)
    db_session.add(sr)
    db_session.commit()
    db_session.add_all([
        Finding(scan_run_id=sr.id, host="app.example.com", severity="medium",
                endpoint="https://app.example.com/search?q=1", vuln_type="generic-sqli",
                vuln_class="sqli", source_tool="nuclei", curl_command="curl x"),
        Finding(scan_run_id=sr.id, host="app.example.com", severity="high",
                endpoint="https://app.example.com/search?q=test", vuln_type="SQL Injection",
                source_tool="strix", confirmed_by_strix=True),
    ])
    db_session.commit()
    result = correlate(db_session, p)
    assert len(result) == 1
    cf = result[0]
    assert cf.sources == "nuclei,strix"
    assert cf.confidence == "medium"
    assert cf.vuln_class == "sqli"
    assert cf.reproduction == "curl x"


def test_legacy_correlated_row_is_migrated_not_duplicated(db_session):
    p = _program(db_session)
    sr = ScanRun(program_id=p.id, run_name="r", tool="nuclei", status=ScanStatus.done)
    db_session.add(sr)
    db_session.commit()
    db_session.add(Finding(scan_run_id=sr.id, host="app.example.com", severity="low",
                           endpoint="https://app.example.com/x", vuln_type="xss",
                           source_tool="nuclei"))
    old = CorrelatedFinding(
        program_id=p.id, correlation_key="app.example.com|https://app.example.com/x|xss",
        host="app.example.com", vuln_type="xss", sources="nuclei", cvss_manual=True,
        cvss_score=9.9,
    )
    db_session.add(old)
    db_session.commit()
    correlate(db_session, p)
    rows = db_session.query(CorrelatedFinding).all()
    assert len(rows) == 1
    assert rows[0].cvss_score == 9.9           # تعديل الباحث محفوظ
    assert rows[0].correlation_key == correlation_key("app.example.com", "https://app.example.com/x", "xss")


def test_dedupe_no_substring_host_match():
    f = SimpleNamespace(host="data.com", vuln_type="SQL Injection")
    prior = SimpleNamespace(title="SQLi in login", asset="a.com", source="me")
    assert is_duplicate(f, [prior]) is None
    f2 = SimpleNamespace(host="api.a.com", vuln_type="SQL Injection")
    assert is_duplicate(f2, [prior]) is prior


# ── التحقق ──

def _correlated_nuclei(db, p, template="exposed-panel", url="https://api.example.com/admin"):
    _host(db, p, "api.example.com")
    scan_hosts(db, p, ScanTools(nuclei=lambda t: [_nuclei_item(url, template)]))
    return correlate(db, p)[0]


def test_verify_marks_reproduced_as_high_confidence(db_session):
    p = _program(db_session)
    cf = _correlated_nuclei(db_session, p)
    calls = []

    def rerun(target, template):
        calls.append((target, template))
        return [_nuclei_item(target, template)]

    stats = verify_findings(db_session, p, rerun)
    assert calls == [("https://api.example.com/admin", "exposed-panel")]
    assert stats["verified"] == 1
    assert cf.verified is True and cf.confidence == "high"
    assert cf.status.value == "needs_review"      # التأكيد النهائي يبقى بشريًا


def test_verify_not_reproduced_stays_low(db_session):
    p = _program(db_session)
    cf = _correlated_nuclei(db_session, p)
    stats = verify_findings(db_session, p, lambda t, tid: [])
    assert stats["not_reproduced"] == 1
    assert cf.verified is False and cf.confidence == "low"


def test_verify_tool_error_is_not_a_negative(db_session):
    p = _program(db_session)
    cf = _correlated_nuclei(db_session, p)

    def broken(t, tid):
        raise tools.ToolError("x")

    stats = verify_findings(db_session, p, broken)
    assert stats == {"checked": 1, "verified": 0, "not_reproduced": 0, "skipped": 0, "errors": 1}
    assert cf.verified is False


def test_verify_respects_scope_changes(db_session):
    p = _program(db_session)
    _correlated_nuclei(db_session, p)
    for a in p.scope_assets:          # خرج كل شيء من النطاق بعد الفحص
        a.active = False
    db_session.commit()
    called = []
    stats = verify_findings(db_session, p, lambda t, tid: called.append(t) or [])
    assert called == [] and stats["skipped"] == 1
    assert db_session.query(AuditLog).filter_by(action="verify_scope_block").count() == 1


# ── recon ──

def test_recon_probes_extra_ports_and_flags_wildcard_dns(db_session):
    p = _program(db_session)

    def httpx(hosts):
        return [{"input": h, "url": f"https://{h}", "status_code": 200} for h in hosts]

    def httpx_ports(hosts, ports):
        assert ports == [8080]
        return [{"input": h, "url": f"http://{h}:8080", "status_code": 200} for h in hosts]

    def dnsx(hosts):
        out = {h: ["9.9.9.9"] for h in hosts}       # wildcard: كل اسم يحلّ لنفس العنوان
        out["real.example.com"] = ["1.2.3.4"]
        return out

    rt = ReconTools(
        subfinder=lambda d: ["real.example.com", "ghost.example.com"],
        httpx=httpx, naabu=lambda h: [443, 8080], dnsx=dnsx, httpx_ports=httpx_ports,
    )
    hosts = {h.hostname: h for h in run_full_recon(db_session, p, "example.com", rt)}
    assert hosts["real.example.com"].dns_wildcard is False
    assert hosts["real.example.com"].ip == "1.2.3.4"
    assert hosts["ghost.example.com"].dns_wildcard is True
    assert hosts["example.com"].dns_wildcard is False          # البذرة نفسها ليست وهمية
    assert hosts["real.example.com"].urls.splitlines() == [
        "https://real.example.com", "http://real.example.com:8080",
    ]
