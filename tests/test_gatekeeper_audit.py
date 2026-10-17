"""اختبار أن Scope Gatekeeper يسجّل كل قرار في audit_log."""

from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset
from api.services.scope_gatekeeper import check_target


def _program_with_scope(db):
    prog = Program(name="Demo", handle="demo")
    prog.scope_assets = [
        ScopeAsset(kind=AssetKind.wildcard, identifier="*.example.com", in_scope=True),
        ScopeAsset(kind=AssetKind.domain, identifier="secret.example.com", in_scope=False),
    ]
    db.add(prog)
    db.commit()
    db.refresh(prog)
    return prog


def test_allow_decision_is_audited(db_session):
    prog = _program_with_scope(db_session)
    decision = check_target(db_session, prog, "api.example.com", actor="tester")
    assert decision.allowed is True

    rows = db_session.query(AuditLog).all()
    assert len(rows) == 1
    assert rows[0].decision == "allow"
    assert rows[0].target_value == "api.example.com"
    assert rows[0].actor == "tester"


def test_deny_decision_is_audited(db_session):
    prog = _program_with_scope(db_session)
    decision = check_target(db_session, prog, "secret.example.com")
    assert decision.allowed is False

    row = db_session.query(AuditLog).one()
    assert row.decision == "deny"
