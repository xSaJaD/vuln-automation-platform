"""فحص IDOR / وصول غير مصرّح (Broken Access Control) — تفاضلي بين حسابين.

الفكرة (معيار IDOR الكلاسيكي):
  1. الحساب A يملك مرجع كائن (رابط لبياناته الخاصة، فيه marker يميّزه مثل اسمه/معرّفه).
  2. نطلب نفس الرابط بجلسة الحساب B. إن رأى B بيانات A (200 + نفس الـ marker) => IDOR.
  3. نطلب نفس الرابط بلا جلسة. إن رآه المجهول => المورد عام (تسريب وصول أشدّ).

الطلبات محقونة (requester) حتى تُختبَر بلا شبكة. كل رابط يُعاد التحقق من نطاقه
قبل أي طلب — جلسة B لا تُستخدم إطلاقًا خارج نطاق البرنامج.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from api.services.scope_matching import Decision, ScopeRule, evaluate, host_of
from api.services.similarity import is_same_resource


@dataclass(frozen=True)
class OwnedResource:
    """مرجع كائن يملكه حساب: رابط خاص + نص يميّز بيانات المالك داخل الرد."""

    url: str
    owner_label: str
    marker: str


@dataclass(frozen=True)
class Session:
    label: str | None                 # None = مجهول (بلا مصادقة)
    cookies: dict[str, str] = field(default_factory=dict)
    token: str | None = None


@dataclass
class HttpResponse:
    status_code: int
    body: str = ""


# requester(session, url) -> HttpResponse
Requester = Callable[[Session, str], HttpResponse]


@dataclass
class IdorFinding:
    url: str
    owner_label: str
    accessor_label: str | None        # None => وصول عام بلا مصادقة
    vuln_class: str                   # idor | broken-access-control
    severity: str
    evidence: str


def _accessible(res: HttpResponse, marker: str) -> bool:
    return res.status_code == 200 and bool(marker) and marker in (res.body or "")


def find_idor(
    resources: list[OwnedResource],
    sessions: list[Session],
    requester: Requester,
    rules: list[ScopeRule],
    *,
    on_scope_block: Callable[[str, Decision], None] | None = None,
) -> list[IdorFinding]:
    """لكل مورد يملكه A: يحاول الوصول إليه بكل جلسة أخرى + بلا جلسة."""
    findings: list[IdorFinding] = []
    by_label = {s.label: s for s in sessions}
    anon = by_label.get(None, Session(label=None))

    for res_def in resources:
        decision = evaluate(res_def.url, rules)
        if not decision.allowed:
            if on_scope_block:
                on_scope_block(res_def.url, decision)
            continue
        host = host_of(res_def.url)

        # 1) وصول عام بلا مصادقة = أخطر (المورد مكشوف للكل).
        anon_res = requester(anon, res_def.url)
        if _accessible(anon_res, res_def.marker):
            findings.append(IdorFinding(
                url=res_def.url, owner_label=res_def.owner_label, accessor_label=None,
                vuln_class="broken-access-control", severity="high",
                evidence=f"مورد خاص بـ {res_def.owner_label} على {host} يُقرأ بلا مصادقة "
                         f"(marker='{res_def.marker}')",
            ))
            continue  # إن كان عامًا فلا معنى لاختبار الوصول المتبادل

        # 2) وصول متبادل بين حسابين (IDOR أفقي).
        for sess in sessions:
            if sess.label in (None, res_def.owner_label):
                continue
            other = requester(sess, res_def.url)
            if _accessible(other, res_def.marker):
                findings.append(IdorFinding(
                    url=res_def.url, owner_label=res_def.owner_label, accessor_label=sess.label,
                    vuln_class="idor", severity="high",
                    evidence=f"الحساب {sess.label} قرأ مورد الحساب {res_def.owner_label} "
                             f"على {host} (marker='{res_def.marker}', HTTP {other.status_code})",
                ))
    return findings


_ID_IN_PATH = re.compile(r"(/)(\d+)(/|$|\?)")
_ID_IN_QUERY = re.compile(r"([?&][\w-]*id[\w-]*=)(\d+)", re.I)


def _baseline_url(url: str) -> str:
    """رابط بمعرّف شبه مؤكّد عدم وجوده — لقياس رد الخطأ (baseline)."""
    bogus = "999999999"
    if _ID_IN_PATH.search(url):
        return _ID_IN_PATH.sub(rf"\g<1>{bogus}\g<3>", url, count=1)
    if _ID_IN_QUERY.search(url):
        return _ID_IN_QUERY.sub(rf"\g<1>{bogus}", url, count=1)
    return url.rstrip("/") + "/" + bogus


def find_idor_compare(
    resources: list[OwnedResource],
    sessions: list[Session],
    requester: Requester,
    rules: list[ScopeRule],
    *,
    on_scope_block: Callable[[str, Decision], None] | None = None,
) -> list[IdorFinding]:
    """كشف IDOR بالمقارنة الثلاثية (رد A ~ رد B، ويختلف عن رد الخطأ) — بلا marker.

    أدقّ من مطابقة النص: يعمل حتى لو لم تظهر بيانات المالك حرفيًا في الرد.
    """
    by_label = {s.label: s for s in sessions}
    findings: list[IdorFinding] = []

    for res_def in resources:
        decision = evaluate(res_def.url, rules)
        if not decision.allowed:
            if on_scope_block:
                on_scope_block(res_def.url, decision)
            continue
        owner = by_label.get(res_def.owner_label)
        if owner is None:
            continue
        host = host_of(res_def.url)

        owner_res = requester(owner, res_def.url)
        if owner_res.status_code != 200:     # المالك نفسه لا يصله => لا قياس
            continue
        error_res = requester(owner, _baseline_url(res_def.url))

        for sess in sessions:
            if sess.label in (None, res_def.owner_label):
                continue
            other = requester(sess, res_def.url)
            if other.status_code == 200 and is_same_resource(
                owner_res.body, other.body, error_res.body
            ):
                findings.append(IdorFinding(
                    url=res_def.url, owner_label=res_def.owner_label, accessor_label=sess.label,
                    vuln_class="idor", severity="high",
                    evidence=f"رد الحساب {sess.label} يطابق رد المالك {res_def.owner_label} "
                             f"على {host} ويختلف عن رد الخطأ (تشابه عالٍ) — IDOR مؤكّد بالمقارنة",
                ))
    return findings
