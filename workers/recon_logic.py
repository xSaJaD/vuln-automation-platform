"""منطق تنسيق الـ recon — قابل للاختبار، مع فرض النطاق في كل خطوة.

الأدوات تُحقَن عبر ReconTools حتى يمكن استبدالها ببدائل وهمية في الاختبارات.

الضمانات الأمنية:
  • كل مضيف مكتشَف يمر عبر Scope Gatekeeper ويُسجَّل في audit_log.
  • httpx يُطبَّق على المضيفات ضمن النطاق فقط.
  • naabu يُطبَّق على المضيفات الحيّة ضمن النطاق فقط.
  • المضيفات خارج النطاق تُخزَّن للتوثيق لكن لا تُفحص إطلاقًا.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.program import Program
from api.models.recon import Host
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import evaluate


@dataclass
class ReconTools:
    subfinder: Callable[[str], list[str]]
    httpx: Callable[[list[str]], list[dict]]
    naabu: Callable[[str], list[int]]


def _audit(db: Session, program_id: int, name: str, allowed: bool, reason: str, actor: str) -> None:
    db.add(
        AuditLog(
            action="recon_scope_check",
            target_value=name,
            program_id=program_id,
            decision="allow" if allowed else "deny",
            reason=reason,
            actor=actor,
        )
    )


def discover_subdomains(
    db: Session, program: Program, seed: str, tools: ReconTools, actor: str = "recon"
) -> list[Host]:
    """subfinder + تقييم النطاق لكل نتيجة. يُخزّن الكل مع علم in_scope."""
    rules = rules_for(program)
    names = set(tools.subfinder(seed)) | {seed}

    hosts: list[Host] = []
    for name in sorted(names):
        decision = evaluate(name, rules)
        _audit(db, program.id, name, decision.allowed, decision.reason, actor)

        host = (
            db.query(Host).filter_by(program_id=program.id, hostname=name).first()
            or Host(program_id=program.id, hostname=name, source="subfinder")
        )
        host.in_scope = decision.allowed
        if host.id is None:
            db.add(host)
        hosts.append(host)

    db.commit()
    return hosts


def probe_hosts(db: Session, program: Program, tools: ReconTools) -> list[Host]:
    """httpx على المضيفات ضمن النطاق فقط."""
    scoped = db.query(Host).filter_by(program_id=program.id, in_scope=True).all()
    names = [h.hostname for h in scoped]

    results = {
        (r.get("input") or r.get("host")): r
        for r in tools.httpx(names)
    }
    for host in scoped:
        r = results.get(host.hostname)
        if not r:
            continue
        host.is_live = True
        host.http_status = r.get("status_code")
        title = r.get("title")
        host.title = title[:300] if title else None
        tech = r.get("tech") or r.get("technologies")
        host.tech = ",".join(tech) if isinstance(tech, list) else (tech or None)
        host.ip = r.get("host") if r.get("host") != host.hostname else host.ip

    db.commit()
    return [h for h in scoped if h.is_live]


def scan_ports(db: Session, program: Program, tools: ReconTools) -> list[Host]:
    """naabu على المضيفات الحيّة ضمن النطاق فقط."""
    live = db.query(Host).filter_by(program_id=program.id, in_scope=True, is_live=True).all()
    for host in live:
        ports = tools.naabu(host.hostname)
        host.open_ports = ",".join(str(p) for p in ports) if ports else None
    db.commit()
    return live


def run_full_recon(
    db: Session, program: Program, seed: str, tools: ReconTools, actor: str = "recon"
) -> list[Host]:
    """السلسلة الكاملة: subfinder → httpx → naabu (مع فرض النطاق)."""
    discover_subdomains(db, program, seed, tools, actor)
    probe_hosts(db, program, tools)
    scan_ports(db, program, tools)
    return db.query(Host).filter_by(program_id=program.id).all()
