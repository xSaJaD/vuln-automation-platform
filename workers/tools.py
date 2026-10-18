"""أغلفة subprocess لأدوات ProjectDiscovery (subfinder, httpx, naabu).

تعمل داخل حاوية الـ worker حيث تكون الأدوات مثبّتة. ترجّع بيانات مُحلَّلة.
لا تُستدعى في الاختبارات — الاختبارات تحقن بدائل وهمية (fakes).
"""

from __future__ import annotations

import json
import shutil
import subprocess

DEFAULT_TIMEOUT = 300  # ثانية


class ToolNotFound(RuntimeError):
    pass


def _require(binary: str) -> None:
    if shutil.which(binary) is None:
        raise ToolNotFound(f"{binary} غير مثبّت في بيئة التشغيل (worker)")


def safe_arg(value: str) -> str:
    """يمنع Argument Injection: يرفض القيمة التي تبدأ بـ '-' أو تحوي مسافات/تحكّم.

    هدف/مضيف مثل '-oN/tmp/x' قد يُفسَّر كـ flag للأداة. نرفضه قبل التمرير.
    """
    v = (value or "").strip()
    if not v or v.startswith("-"):
        raise ValueError(f"قيمة غير آمنة (احتمال حقن وسيط): {value!r}")
    if any(c.isspace() or ord(c) < 32 for c in v):
        raise ValueError(f"قيمة تحوي مسافات/محارف تحكّم: {value!r}")
    return v


def run_subfinder(domain: str, timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    """يكتشف النطاقات الفرعية لنطاق معيّن."""
    domain = safe_arg(domain)
    _require("subfinder")
    proc = subprocess.run(
        ["subfinder", "-d", domain, "-silent"],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def run_httpx(hosts: list[str], timeout: int = DEFAULT_TIMEOUT) -> list[dict]:
    """يفحص أي المضيفات حيّة عبر HTTP ويجمع status/title/tech."""
    _require("httpx")
    if not hosts:
        return []
    proc = subprocess.run(
        ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code"],
        input="\n".join(hosts), capture_output=True, text=True, timeout=timeout, check=False,
    )
    results: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def run_nuclei(
    targets: list[str],
    extra_args: list[str] | None = None,
    timeout: int = 1800,
) -> list[dict]:
    """يفحص قائمة أهداف بقوالب nuclei ويرجّع النتائج الخام (JSONL مُحلَّل).

    افتراضيًا بمعدّل مهذّب (-rate-limit) احترامًا لحدود البرنامج.
    """
    _require("nuclei")
    if not targets:
        return []
    cmd = ["nuclei", "-silent", "-jsonl", "-no-color", "-rate-limit", "50"]
    if extra_args:
        cmd += extra_args
    proc = subprocess.run(
        cmd, input="\n".join(targets), capture_output=True, text=True, timeout=timeout, check=False
    )
    results: list[dict] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def run_naabu(host: str, timeout: int = DEFAULT_TIMEOUT) -> list[int]:
    """يفحص المنافذ (connect scan لتجنّب صلاحيات raw socket)."""
    host = safe_arg(host)
    _require("naabu")
    proc = subprocess.run(
        ["naabu", "-host", host, "-silent", "-json", "-scan-type", "c", "-top-ports", "100"],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    ports: set[int] = set()
    for line in proc.stdout.splitlines():
        try:
            ports.add(int(json.loads(line)["port"]))
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue
    return sorted(ports)
