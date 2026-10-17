"""منطق مطابقة النطاق — نقي تمامًا، بدون قاعدة بيانات. قلب Scope Gatekeeper.

القواعد الحاكمة (الأمان أولًا):
  1. أي تطابق مع قاعدة out-of-scope => رفض فوري (يتغلّب على كل شيء).
  2. وإلا، تطابق مع قاعدة in-scope => قبول.
  3. وإلا (لا تطابق إطلاقًا) => رفض افتراضي.

wildcard (*.example.com) يطابق النطاقات الفرعية فقط، وليس الـ apex.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopeRule:
    kind: str          # domain | wildcard | ip | cidr | url | repo
    identifier: str
    in_scope: bool     # False => out-of-scope (مُستبعَد صراحة)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    matched: str | None = None


def host_of(value: str) -> str:
    """يستخرج اسم المضيف من رابط أو نطاق أو IP (بدون scheme/path/port)."""
    v = value.strip()
    if "://" in v:
        v = urlparse(v).hostname or ""
    else:
        v = v.split("/", 1)[0].split(":", 1)[0]
    return v.lower().rstrip(".")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _repo_norm(value: str) -> str:
    v = value.strip().lower()
    v = v.split("://", 1)[-1]
    v = v.replace("git@github.com:", "github.com/")
    v = v.removesuffix(".git").rstrip("/")
    return v


def _domain_matches(host: str, rule: ScopeRule) -> bool:
    rid = rule.identifier.lower().rstrip(".")
    if rule.kind == "wildcard":
        base = rid[2:] if rid.startswith("*.") else rid
        return host.endswith("." + base)  # النطاقات الفرعية فقط
    if rule.kind in ("domain", "url"):
        return host == host_of(rid)
    return False


def _ip_matches(ip_str: str, rule: ScopeRule) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    try:
        if rule.kind == "ip":
            return ip == ipaddress.ip_address(rule.identifier)
        if rule.kind == "cidr":
            return ip in ipaddress.ip_network(rule.identifier, strict=False)
    except ValueError:
        return False
    return False


def _matches(target: str, host: str, target_is_ip: bool, rule: ScopeRule) -> bool:
    if rule.kind == "repo":
        return _repo_norm(target) == _repo_norm(rule.identifier)
    if target_is_ip:
        return _ip_matches(host, rule)
    return _domain_matches(host, rule)


def evaluate(target: str, rules: list[ScopeRule]) -> Decision:
    """يقرّر إن كان الهدف مسموحًا بناءً على قواعد نطاق البرنامج."""
    raw = (target or "").strip()
    if not raw:
        return Decision(False, "هدف فارغ")

    host = host_of(raw)
    target_is_ip = _is_ip(host)

    # 1) out-of-scope يتغلّب دائمًا
    for rule in rules:
        if not rule.in_scope and _matches(raw, host, target_is_ip, rule):
            return Decision(False, f"الهدف مُستبعَد صراحة ({rule.identifier})", rule.identifier)

    # 2) in-scope
    for rule in rules:
        if rule.in_scope and _matches(raw, host, target_is_ip, rule):
            return Decision(True, f"ضمن النطاق ({rule.identifier})", rule.identifier)

    # 3) لا تطابق إطلاقًا => رفض افتراضي
    return Decision(False, "الهدف غير موجود في نطاق البرنامج")
