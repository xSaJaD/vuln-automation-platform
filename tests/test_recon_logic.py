"""اختبارات منطق الـ recon مع أدوات وهمية — معيار قبول Phase 3.

الأهم: التأكد أن المضيفات خارج النطاق لا تُفحص إطلاقًا.
"""

from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset
from workers.recon_logic import (
    ReconTools,
    discover_subdomains,
    probe_hosts,
    run_full_recon,
)


def _program(db):
    p = Program(name="Demo", handle="demo")
    p.scope_assets = [
        ScopeAsset(kind=AssetKind.domain, identifier="example.com", in_scope=True),
        ScopeAsset(kind=AssetKind.wildcard, identifier="*.example.com", in_scope=True),
    ]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _tools(subs, httpx_fn=None, ports=None):
    def default_httpx(hosts):
        return [{"input": h, "status_code": 200, "title": "T", "tech": ["nginx"]} for h in hosts]

    return ReconTools(
        subfinder=lambda d: subs,
        httpx=httpx_fn or default_httpx,
        naabu=lambda h: ports if ports is not None else [80, 443],
    )


def test_discovered_hosts_scope_flagged_and_audited(db_session):
    p = _program(db_session)
    tools = _tools(["api.example.com", "evil.com", "app.example.com"])

    hosts = discover_subdomains(db_session, p, "example.com", tools)
    by = {h.hostname: h for h in hosts}

    assert by["api.example.com"].in_scope is True
    assert by["app.example.com"].in_scope is True
    assert by["evil.com"].in_scope is False  # مكتشَف لكن خارج النطاق

    # كل قرار سُجِّل في audit_log
    audited = db_session.query(AuditLog).filter_by(action="recon_scope_check").count()
    assert audited == len(by)


def test_out_of_scope_host_never_probed(db_session):
    p = _program(db_session)
    discover_subdomains(db_session, p, "example.com", _tools(["api.example.com", "evil.com"]))

    probed: dict = {}

    def spy_httpx(hosts):
        probed["hosts"] = list(hosts)
        return [{"input": h, "status_code": 200, "title": "ok", "tech": ["nginx"]} for h in hosts]

    tools = ReconTools(subfinder=lambda d: [], httpx=spy_httpx, naabu=lambda h: [443])
    live = probe_hosts(db_session, p, tools)

    assert "evil.com" not in probed["hosts"]        # خارج النطاق لم يُفحص
    assert "api.example.com" in probed["hosts"]
    assert all(h.in_scope for h in live)


def test_full_recon_chain(db_session):
    p = _program(db_session)
    hosts = run_full_recon(db_session, p, "example.com", _tools(["api.example.com", "evil.com"]))

    api_host = next(h for h in hosts if h.hostname == "api.example.com")
    evil_host = next(h for h in hosts if h.hostname == "evil.com")

    assert api_host.is_live is True
    assert api_host.open_ports == "80,443"
    assert api_host.tech == "nginx"

    # evil.com مُخزَّن للتوثيق لكن لم يُفحص: غير حيّ ولا منافذ
    assert evil_host.in_scope is False
    assert evil_host.is_live is False
    assert evil_host.open_ports is None


def test_rerun_recon_is_idempotent(db_session):
    """إعادة التشغيل لا تُنشئ مضيفات مكرّرة."""
    p = _program(db_session)
    discover_subdomains(db_session, p, "example.com", _tools(["api.example.com"]))
    discover_subdomains(db_session, p, "example.com", _tools(["api.example.com"]))

    from api.models.recon import Host

    count = db_session.query(Host).filter_by(hostname="api.example.com").count()
    assert count == 1
