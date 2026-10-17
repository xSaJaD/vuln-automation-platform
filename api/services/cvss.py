"""حاسبة CVSS v3.1 (Base Score) + اقتراح تلقائي حسب نوع الثغرة.

الباحث يقدر يعدّل يدويًا (vector أو score). الحساب يتبع معادلة CVSS 3.1 الرسمية.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    # تقريب CVSS الرسمي لأعلى إلى خانة عشرية واحدة.
    return math.ceil(round(value * 100000) / 100000 * 10) / 10


def _parse(vector: str) -> dict[str, str]:
    body = vector.upper().replace("CVSS:3.1/", "").replace("CVSS:3.0/", "")
    return dict(part.split(":") for part in body.split("/") if ":" in part)


def base_score(vector: str) -> float:
    """يحسب Base Score من vector مثل AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H."""
    m = _parse(vector)
    scope_changed = m.get("S") == "C"

    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    pr = _PR_C[m["PR"]] if scope_changed else _PR_U[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]

    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return _roundup(min(raw, 10.0))


def severity_from_score(score: float) -> str:
    if score <= 0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# vectors افتراضية لأنواع ثغرات شائعة
_TYPE_VECTORS = {
    "rce": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssti": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "sqli": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "sql-injection": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "ssrf": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "idor": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "lfi": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "xss": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
}

# بديل حسب الخطورة النصية إن لم يُعرف النوع
_SEVERITY_VECTORS = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "medium": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "low": "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    "info": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}


def auto_cvss(vuln_type: str | None, severity: str | None) -> tuple[float, str]:
    """يقترح (score, vector) تلقائيًا من نوع الثغرة، وإلا من الخطورة النصية."""
    vt = (vuln_type or "").lower()
    vector = None
    for key, vec in _TYPE_VECTORS.items():
        if key in vt:
            vector = vec
            break
    if vector is None:
        vector = _SEVERITY_VECTORS.get((severity or "").lower(), _SEVERITY_VECTORS["info"])

    return base_score(vector), f"CVSS:3.1/{vector}"
