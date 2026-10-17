"""Scope Gatekeeper — الطبقة المرتبطة بقاعدة البيانات.

يحمّل نطاق البرنامج، يستدعي محرّك المطابقة النقي، ويسجّل كل قرار في audit_log.
**كل هدف يجب أن يمر من هنا قبل أي recon أو scan. لا مسار يتجاوز هذا.**
"""

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.program import Program
from api.services.scope_matching import Decision, ScopeRule, evaluate


def rules_for(program: Program) -> list[ScopeRule]:
    return [
        ScopeRule(
            kind=asset.kind.value,
            identifier=asset.identifier,
            in_scope=asset.in_scope,
        )
        for asset in program.scope_assets
    ]


def check_target(
    db: Session,
    program: Program,
    target_value: str,
    actor: str = "system",
) -> Decision:
    """يقرّر ويسجّل في audit_log ثم يرجّع القرار."""
    decision = evaluate(target_value, rules_for(program))

    db.add(
        AuditLog(
            action="scope_check",
            target_value=target_value,
            program_id=program.id,
            decision="allow" if decision.allowed else "deny",
            reason=decision.reason,
            actor=actor,
        )
    )
    db.commit()
    return decision
