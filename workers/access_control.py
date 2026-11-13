"""فحص التصعيد الرأسي للصلاحيات (Vertical Privilege Escalation) + فحص الـ methods.

يطلب endpoints حسّاسة/إدارية بجلسة مستخدم عادي: لو نجحت (200) بدل الرفض (401/403)
=> خلل تحكّم بالوصول. ويجرّب methods معدِّلة (DELETE/PUT) على مسارات القراءة. نقي.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from api.services.scope_matching import ScopeRule, evaluate, host_of
from workers.idor_logic import IdorFinding, Session

# دلائل مسار إداري/حسّاس.
_ADMIN_HINTS = re.compile(
    r"(?i)/(admin|administrator|manage|dashboard|internal|config|settings|users?|accounts?|"
    r"roles?|permissions?|audit|billing|invoices?|delete|debug|actuator|metrics)(/|$|\?)"
)
_WRITE_METHODS = ("DELETE", "PUT", "PATCH", "POST")


@dataclass
class MethodResponse:
    status_code: int
    body: str = ""


# requester(session, url, method) -> MethodResponse
MethodRequester = Callable[[Session, str, str], MethodResponse]

DENIED = {401, 403, 404, 405}


def is_sensitive(url: str) -> bool:
    return bool(_ADMIN_HINTS.search(url))


def find_privilege_issues(
    endpoints: list[str],
    low_priv: Session,
    requester: MethodRequester,
    rules: list[ScopeRule],
    *,
    anon: Session | None = None,
    check_writes: bool = True,
    on_scope_block: Callable[[str], None] | None = None,
) -> list[IdorFinding]:
    """يطلب الـ endpoints الحسّاسة بجلسة مستخدم عادي (وبلا مصادقة) ويرصد الوصول غير المصرّح."""
    anon = anon or Session(label=None)
    findings: list[IdorFinding] = []

    for url in endpoints:
        if not is_sensitive(url):
            continue
        if not evaluate(url, rules).allowed:
            if on_scope_block:
                on_scope_block(url)
            continue
        host = host_of(url)

        # قراءة بجلسة مستخدم عادي: 200 على مسار إداري => تصعيد صلاحيات.
        res = requester(low_priv, url, "GET")
        if res.status_code == 200:
            # لو المجهول أيضًا يصله => مكشوف للعموم (أشدّ).
            anon_res = requester(anon, url, "GET")
            public = anon_res.status_code == 200
            findings.append(IdorFinding(
                url=url, owner_label="admin", accessor_label=None if public else low_priv.label,
                vuln_class="broken-access-control" if public else "privilege-escalation",
                severity="high",
                evidence=(f"مسار إداري {url} على {host} يُقرأ "
                          + ("بلا مصادقة" if public else f"بجلسة مستخدم عادي ({low_priv.label})")),
            ))
            continue

        # methods معدِّلة على مسار محمي: استجابة غير رافضة => خلل محتمل.
        if check_writes:
            for method in _WRITE_METHODS:
                mres = requester(low_priv, url, method)
                if mres.status_code not in DENIED and mres.status_code < 500:
                    findings.append(IdorFinding(
                        url=url, owner_label="admin", accessor_label=low_priv.label,
                        vuln_class="broken-access-control", severity="high",
                        evidence=f"{method} {url} على {host} مقبول بجلسة مستخدم عادي "
                                 f"(HTTP {mres.status_code}) — تحكّم وصول مكسور",
                    ))
                    break
    return findings
