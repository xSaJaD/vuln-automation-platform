"""تأكيد XSS المخزّن (Stored/Persistent) — نقي وقابل للاختبار.

XSS المنعكس يظهر في نفس الرد؛ المخزّن يُحقَن في صفحة (تعليق/ملف شخصي) ثم يظهر في
صفحة أخرى. نحقن canary فريدًا في نقطة كتابة، ثم نتصفّح صفحات القراءة ونبحث عنه.

مُرسِل الطلب (probe) محقون. كل رابط يُفترض أنه مرّ الحارس قبل الاستدعاء.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from workers.confirmers import Verdict, inject


@dataclass
class StoredXssProbe:
    write_url: str              # نقطة الكتابة (POST/GET فيه المعامل)
    write_param: str            # المعامل الذي يُخزَّن
    read_urls: list[str]        # صفحات القراءة التي قد يظهر فيها المحتوى


def confirm_stored_xss(
    probe, spec: StoredXssProbe, *, submit: Callable[[str, str, str], None] | None = None,
) -> Verdict:
    """يحقن canary فريدًا في نقطة الكتابة ثم يبحث عنه بلا ترميز في صفحات القراءة."""
    canary = "sx" + secrets.token_hex(5)
    payload = f"<svg/onload=alert('{canary}')>"

    if submit is not None:
        submit(spec.write_url, spec.write_param, payload)      # POST فعلي (محقون)
    else:
        probe.get(inject(spec.write_url, spec.write_param, payload))  # نقطة كتابة GET

    for read_url in spec.read_urls:
        r = probe.get(read_url)
        body = (r.text if r else "") or ""
        if payload in body:                 # ظهر بلا ترميز في صفحة أخرى
            return Verdict("confirmed",
                           f"الحمولة المخزّنة ظهرت غير مُرمَّزة في {read_url} — XSS مخزّن")
        if canary in body and payload not in body:
            # ظهر لكن مُرمَّزًا — تخزين بلا تنفيذ (ليس ثغرة مؤكّدة).
            continue
    return Verdict("unconfirmed", "لم تظهر الحمولة المخزّنة غير مُرمَّزة في صفحات القراءة")
