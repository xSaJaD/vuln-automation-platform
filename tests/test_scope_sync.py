"""اختبارات Phase 15 — مزامنة النطاق وقواعد الاشتباك.

معيار القبول: تعديل النطاق (إزالة أصل) ثم مزامنة → الهدف المحذوف يتوقف فحصه.
"""

from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset
from api.services.scope_gatekeeper import check_target, rules_for
from workers.scope_sync import RemoteAsset, fetch_structured_scopes, reconcile_scope


def _program(db):
    p = Program(name="Acme", handle="acme")
    p.scope_assets = [
        ScopeAsset(kind=AssetKind.wildcard, identifier="*.acme.com", in_scope=True, active=True),
        ScopeAsset(kind=AssetKind.wildcard, identifier="*.legacy.com", in_scope=True, active=True),
    ]
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def test_removed_asset_is_deactivated_and_blocks_scan(db_session):
    p = _program(db_session)

    # النطاق البعيد الجديد لم يعد فيه *.legacy.com
    remote = [RemoteAsset(kind="wildcard", identifier="*.acme.com", in_scope=True)]
    result = reconcile_scope(db_session, p, remote)
    assert result["deactivated"] == 1

    db_session.refresh(p)
    legacy = next(a for a in p.scope_assets if a.identifier == "*.legacy.com")
    assert legacy.active is False  # عُطّل

    # هدف كان ضمن *.legacy.com صار مرفوضًا الآن
    assert check_target(db_session, p, "api.legacy.com").allowed is False
    # بينما *.acme.com ما زال مسموحًا
    assert check_target(db_session, p, "app.acme.com").allowed is True

    # سُجِّل التعطيل
    assert db_session.query(AuditLog).filter_by(action="scope_deactivate").count() == 1


def test_sync_adds_new_asset(db_session):
    p = _program(db_session)
    remote = [
        RemoteAsset(kind="wildcard", identifier="*.acme.com", in_scope=True),
        RemoteAsset(kind="wildcard", identifier="*.legacy.com", in_scope=True),
        RemoteAsset(kind="domain", identifier="new.acme.io", in_scope=True),
    ]
    result = reconcile_scope(db_session, p, remote)
    assert result["added"] == 1
    assert check_target(db_session, p, "new.acme.io").allowed is True


def test_rules_for_excludes_inactive(db_session):
    p = _program(db_session)
    p.scope_assets[1].active = False
    db_session.commit()
    idents = [r.identifier for r in rules_for(p)]
    assert "*.acme.com" in idents
    assert "*.legacy.com" not in idents


def test_h1_mapping():
    raw = [
        {"attributes": {"asset_type": "WILDCARD", "asset_identifier": "*.acme.com",
                        "eligible_for_submission": True, "max_severity": "critical"}},
        {"attributes": {"asset_type": "URL", "asset_identifier": "shop.acme.com",
                        "eligible_for_submission": False}},
        {"attributes": {"asset_type": "SOURCE_CODE", "asset_identifier": "github.com/acme/app",
                        "eligible_for_submission": True}},
    ]
    mapped = fetch_structured_scopes("acme", fetcher=lambda h: raw)
    kinds = {m.identifier: (m.kind, m.in_scope) for m in mapped}
    assert kinds["*.acme.com"] == ("wildcard", True)
    assert kinds["shop.acme.com"] == ("domain", False)   # out of scope
    assert kinds["github.com/acme/app"] == ("repo", True)
