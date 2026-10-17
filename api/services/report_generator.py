"""مولّد تقارير المسودّات (Markdown) من finding موحّد مؤكَّد.

التقرير دائمًا **مسودة** — يحمل تنبيهًا صريحًا ولا يُرسَل آليًا إلى HackerOne.
"""

from __future__ import annotations

import os

from api.models.correlation import CorrelatedFinding
from api.models.program import Program

# وصف/أثر/إصلاح/خطوات لكل نوع ثغرة شائع.
_VULN_INFO: dict[str, dict[str, str]] = {
    "sqli": {
        "name": "SQL Injection",
        "desc": "يسمح إدخال غير مُعقَّم بحقن استعلامات SQL وتنفيذها على قاعدة البيانات.",
        "steps": "1. أرسل حمولة حقن في المعامل المتأثر.\n2. راقب تغيّر الاستجابة أو استخراج بيانات.",
        "impact": "تسريب/تعديل بيانات حسّاسة، وربما تجاوز المصادقة أو تنفيذ أوامر.",
        "remediation": "استخدم استعلامات مُعاملة (parameterized queries) و ORM، وتحقّق من المدخلات.",
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "desc": "ينعكس إدخال غير مُعقَّم في الصفحة فيُنفَّذ كـ JavaScript في متصفح الضحية.",
        "steps": "1. أدخل حمولة سكربت في الحقل المتأثر.\n2. تأكد من تنفيذها عند عرض الصفحة.",
        "impact": "سرقة الجلسات/التوكنات، تنفيذ إجراءات نيابة عن المستخدم.",
        "remediation": "رمّز المخرجات (output encoding)، طبّق CSP، ونقِّ المدخلات.",
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "desc": "يجبر الخادم على إرسال طلبات إلى وجهات يحددها المهاجم.",
        "steps": "1. وجّه المعامل إلى عنوان داخلي (مثل metadata).\n2. راقب الاستجابة.",
        "impact": "الوصول لخدمات داخلية وبيانات اعتماد السحابة.",
        "remediation": "قائمة سماح للوجهات، امنع الشبكات الداخلية، وتحقّق من الـ URL.",
    },
    "rce": {
        "name": "Remote Code Execution (RCE)",
        "desc": "يسمح بتنفيذ أوامر/شيفرة عشوائية على الخادم.",
        "steps": "1. أرسل الحمولة في المدخل المتأثر.\n2. تأكد من تنفيذ الأمر.",
        "impact": "سيطرة كاملة على الخادم — أعلى خطورة.",
        "remediation": "تجنّب تمرير مدخلات لأوامر النظام، استخدم قوائم سماح صارمة.",
    },
    "idor": {
        "name": "Insecure Direct Object Reference (IDOR)",
        "desc": "الوصول لموارد مستخدمين آخرين بتغيير معرّف في الطلب.",
        "steps": "1. غيّر معرّف المورد إلى مورد لا تملكه.\n2. تأكد من الوصول.",
        "impact": "كشف/تعديل بيانات مستخدمين آخرين.",
        "remediation": "تحقّق من التفويض على مستوى كل مورد (object-level authz).",
    },
}

_GENERIC = {
    "name": "Security Finding",
    "desc": "ثغرة أمنية مكتشَفة تتطلب التحقق والمراجعة.",
    "steps": "راجع الدليل أدناه لإعادة إنتاج المشكلة.",
    "impact": "يعتمد على السياق — راجِع يدويًا.",
    "remediation": "طبّق أفضل ممارسات الأمان المناسبة لهذا النوع.",
}


def _info_for(vuln_type: str | None) -> dict[str, str]:
    vt = (vuln_type or "").lower()
    for key, info in _VULN_INFO.items():
        if key in vt:
            return info
    return _GENERIC


def render_report(finding: CorrelatedFinding, program: Program) -> str:
    info = _info_for(finding.vuln_type)
    cvss = (
        f"{finding.cvss_score} (`{finding.cvss_vector}`)"
        if finding.cvss_score
        else "غير محدد"
    )
    poc = finding.evidence or "—"

    return f"""# [{finding.severity.upper()}] {info['name']} — {finding.host}

> ⚠️ **مسودة — تتطلب مراجعة بشرية قبل الإرسال. لا تُرسَل آليًا إلى HackerOne.**

- **البرنامج:** {program.name} (`{program.handle}`)
- **الأصل المتأثر:** {finding.host}
- **Endpoint:** {finding.endpoint or '—'}
- **الخطورة:** {finding.severity}
- **CVSS:** {cvss}
- **المصادر:** {finding.sources}
- **مؤكَّد بـ Strix:** {'نعم' if finding.confirmed_by_strix else 'لا'}

## الوصف
{info['desc']}

## خطوات إعادة الإنتاج
{info['steps']}

## الدليل (PoC / Evidence)
```
{poc}
```

## الأثر
{info['impact']}

## التوصية بالإصلاح
{info['remediation']}

---
*وُلّد تلقائيًا كمسودة — راجِع وعدّل قبل أي إرسال يدوي.*
"""


def save_report(out_dir: str, program: Program, finding: CorrelatedFinding, markdown: str) -> str:
    folder = os.path.join(out_dir, program.handle)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"finding-{finding.id}.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(markdown)
    return path
