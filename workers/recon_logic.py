"""منطق تنسيق الـ recon — قابل للاختبار، مع فرض النطاق في كل خطوة.

الأدوات تُحقَن عبر ReconTools حتى يمكن استبدالها ببدائل وهمية في الاختبارات.

الضمانات الأمنية:
  • كل مضيف مكتشَف يمر عبر Scope Gatekeeper ويُسجَّل في audit_log.
  • httpx يُطبَّق على المضيفات ضمن النطاق فقط.
  • naabu يُطبَّق على المضيفات الحيّة ضمن النطاق فقط.
  • المضيفات خارج النطاق تُخزَّن للتوثيق لكن لا تُفحص إطلاقًا.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.program import Program
from api.models.recon import Host
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import evaluate, host_of

STANDARD_WEB_PORTS = {80, 443}


@dataclass
class ReconTools:
    subfinder: Callable[[str], list[str]]
    httpx: Callable[[list[str]], list[dict]]
    naabu: Callable[[str], list[int]]
    # اختياريان (يبقى السلوك القديم بدونهما):
    #   dnsx(hosts) -> {host: [ips]}        حلّ DNS + كشف wildcard
    #   httpx_ports(hosts, ports) -> [dict]  فحص HTTP على منافذ naabu غير القياسية
    dnsx: Callable[[list[str]], dict[str, list[str]]] | None = None
    httpx_ports: Callable[[list[str], list[int]], list[dict]] | None = None


def _merge_urls(host: Host, results: list[dict]) -> None:
    """يضيف روابط httpx الحيّة للمضيف (فقط التي تخصّ المضيف نفسه)."""
    urls = [u for u in (host.urls or "").splitlines() if u.strip()]
    for r in results:
        url = (r.get("url") or "").strip()
        if url and host_of(url) == host.hostname.lower() and url not in urls:
            urls.append(url)
    host.urls = "\n".join(urls) or None


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

    _resolve_dns(seed, [h for h in hosts if h.in_scope], tools)
    db.commit()
    return hosts


def _resolve_dns(seed: str, scoped: list[Host], tools: ReconTools) -> None:
    """يحلّ المضيفات ضمن النطاق ويعلّم ما يحلّ فقط إلى عناوين wildcard DNS.

    نطاق فيه `*.example.com` يُرجِع عنوانًا لأي اسم عشوائي؛ نسأل عن اسم عشوائي
    غير موجود، وأي مضيف كل عناوينه من ذلك الرد يُعلَّم dns_wildcard (مشكوك فيه).
    """
    if tools.dnsx is None or not scoped:
        return
    canary = f"{secrets.token_hex(8)}.{seed.lower()}"
    resolved = tools.dnsx([h.hostname for h in scoped] + [canary])
    wildcard_ips = set(resolved.get(canary, []))
    for host in scoped:
        ips = resolved.get(host.hostname.lower(), [])
        if ips:
            host.ip = ips[0]
        host.dns_wildcard = bool(
            ips and wildcard_ips and host.hostname.lower() != seed.lower()
            and set(ips) <= wildcard_ips
        )


def probe_hosts(db: Session, program: Program, tools: ReconTools) -> list[Host]:
    """httpx على المضيفات ضمن النطاق فقط."""
    scoped = db.query(Host).filter_by(program_id=program.id, in_scope=True).all()
    names = [h.hostname for h in scoped]

    grouped: dict[str, list[dict]] = {}
    for r in tools.httpx(names):
        grouped.setdefault(r.get("input") or r.get("host"), []).append(r)
    for host in scoped:
        rs = grouped.get(host.hostname)
        if not rs:
            continue
        r = rs[0]
        host.is_live = True
        _merge_urls(host, rs)
        host.http_status = r.get("status_code")
        title = r.get("title")
        host.title = title[:300] if title else None
        tech = r.get("tech") or r.get("technologies")
        host.tech = ",".join(tech) if isinstance(tech, list) else (tech or None)
        if r.get("host") and r.get("host") != host.hostname:
            host.ip = r["host"]
        # كشف الحظر (WAF) من كود الحالة والعنوان.
        from api.services.block_detection import looks_blocked

        host.block_status = "blocked" if looks_blocked(host.http_status, host.title or "") else "clean"

    db.commit()
    return [h for h in scoped if h.is_live]


def scan_ports(db: Session, program: Program, tools: ReconTools) -> list[Host]:
    """naabu على المضيفات الحيّة ضمن النطاق فقط."""
    live = db.query(Host).filter_by(program_id=program.id, in_scope=True, is_live=True).all()
    for host in live:
        ports = tools.naabu(host.hostname)
        host.open_ports = ",".join(str(p) for p in ports) if ports else None
        # خدمات الويب على منافذ غير قياسية (8080، 8443…) كانت تفوت الفحص كليًا.
        extra = [p for p in ports if p not in STANDARD_WEB_PORTS]
        if extra and tools.httpx_ports is not None:
            _merge_urls(host, tools.httpx_ports([host.hostname], extra))
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
