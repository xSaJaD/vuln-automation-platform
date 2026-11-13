"""أغلفة subprocess لأدوات ProjectDiscovery (subfinder, dnsx, httpx, naabu, nuclei).

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


class ToolError(RuntimeError):
    """الأداة فشلت (exit code ≠ 0). يُرفع حتى لا يُقرأ الفشل كـ "لا نتائج"."""


def _jsonl(stdout: str) -> list[dict]:
    results: list[dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            results.append(item)
    return results


def _check(binary: str, proc: subprocess.CompletedProcess, has_output: bool) -> None:
    """فشل بلا أي مخرجات => خطأ صريح. (فشل مع مخرجات جزئية: نُبقي الجزئي.)"""
    if proc.returncode != 0 and not has_output:
        tail = (proc.stderr or "").strip()[-500:]
        raise ToolError(f"{binary} فشل (exit={proc.returncode}): {tail}")


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
    """يكتشف النطاقات الفرعية لنطاق معيّن (كل المصادر السلبية)."""
    domain = safe_arg(domain)
    _require("subfinder")
    proc = subprocess.run(
        ["subfinder", "-d", domain, "-all", "-silent"],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    names = [line.strip().lower() for line in proc.stdout.splitlines() if line.strip()]
    _check("subfinder", proc, bool(names))
    return names


def run_dnsx(hosts: list[str], timeout: int = DEFAULT_TIMEOUT) -> dict[str, list[str]]:
    """يحلّ أسماء المضيفات (A records). يرجّع {host: [ips]} للأسماء التي تُحَلّ فقط."""
    _require("dnsx")
    if not hosts:
        return {}
    proc = subprocess.run(
        ["dnsx", "-silent", "-json", "-a", "-resp"],
        input="\n".join(hosts), capture_output=True, text=True, timeout=timeout, check=False,
    )
    items = _jsonl(proc.stdout)
    _check("dnsx", proc, bool(items))
    resolved: dict[str, list[str]] = {}
    for item in items:
        name = (item.get("host") or "").lower().rstrip(".")
        ips = item.get("a") or []
        if name and ips:
            resolved[name] = list(ips)
    return resolved


def run_httpx(
    hosts: list[str], ports: list[int] | None = None, timeout: int = DEFAULT_TIMEOUT
) -> list[dict]:
    """يفحص أي المضيفات حيّة عبر HTTP ويجمع status/title/tech.

    ports: منافذ إضافية (مثلًا من naabu) — وإلا المنافذ الافتراضية 80/443.
    """
    _require("httpx")
    if not hosts:
        return []
    cmd = ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code"]
    if ports:
        cmd += ["-ports", ",".join(str(int(p)) for p in ports)]
    proc = subprocess.run(
        cmd, input="\n".join(hosts), capture_output=True, text=True, timeout=timeout, check=False,
    )
    results = _jsonl(proc.stdout)
    _check("httpx", proc, bool(results))
    return results


def nuclei_command(
    rate_per_min: int | None = None,
    template_ids: list[str] | None = None,
    extra_args: list[str] | None = None,
    headers: dict[str, str] | None = None,
    dast: bool = False,
) -> list[str]:
    """يبني أمر nuclei. rate_per_min=حد البرنامج (ROE)؛ headers=فحص مصادَق؛ dast=فحص معاملات."""
    cmd = ["nuclei", "-silent", "-jsonl", "-no-color", "-retries", "2", "-timeout", "10"]
    if rate_per_min and rate_per_min > 0:
        cmd += ["-rate-limit-minute", str(int(rate_per_min))]
    else:
        cmd += ["-rate-limit", "50"]
    if template_ids:
        cmd += ["-id", ",".join(safe_arg(t) for t in template_ids)]
    for name, value in (headers or {}).items():
        # ترويسات المصادقة (Cookie/Authorization) — تُمرَّر كما هي بلا سطور تحكّم.
        if "\n" in name or "\r" in name or "\n" in value or "\r" in value:
            raise ValueError("ترويسة تحوي محارف تحكّم")
        cmd += ["-H", f"{name}: {value}"]
    if dast:
        cmd += ["-dast"]
    if extra_args:
        cmd += extra_args
    return cmd


def run_nuclei(
    targets: list[str],
    extra_args: list[str] | None = None,
    timeout: int = 1800,
    rate_per_min: int | None = None,
    template_ids: list[str] | None = None,
    headers: dict[str, str] | None = None,
    dast: bool = False,
) -> list[dict]:
    """يفحص قائمة أهداف بقوالب nuclei ويرجّع النتائج الخام (JSONL مُحلَّل).

    headers: فحص مصادَق (Cookie/Authorization). dast: فحص المعاملات.
    يرفع ToolError لو فشل nuclei بلا مخرجات — الفشل ليس "لا ثغرات".
    """
    _require("nuclei")
    if not targets:
        return []
    cmd = nuclei_command(rate_per_min, template_ids, extra_args, headers=headers, dast=dast)
    proc = subprocess.run(
        cmd, input="\n".join(targets), capture_output=True, text=True, timeout=timeout, check=False
    )
    results = _jsonl(proc.stdout)
    _check("nuclei", proc, bool(results))
    return results


def run_katana(
    seed: str,
    cookie_header: str | None = None,
    depth: int = 3,
    timeout: int = DEFAULT_TIMEOUT,
    form_fill: bool = True,
) -> list[str]:
    """يزحف من رابط بداية ويكتشف الصفحات والروابط البارامترية (مع جلسة اختيارية).

    form_fill=True يفعّل ملء النماذج تلقائيًا (-aff) وزحف الـ JavaScript (-jc) حتى
    يكتشف بارامترات النماذج (مثل ?id=&Submit=) — يرفع تغطية الفحص كثيرًا. يُستخدم
    على أهداف مصرّح بها فقط لأنه يُرسل النماذج.
    """
    seed = safe_arg(seed)
    _require("katana")
    cmd = ["katana", "-u", seed, "-silent", "-jsonl", "-nc", "-d", str(int(depth))]
    if form_fill:
        cmd += ["-jc", "-aff", "-kf", "all"]
    if cookie_header:
        cmd += ["-H", "Cookie: " + cookie_header]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    urls: set[str] = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        ep = obj.get("endpoint") or (obj.get("request") or {}).get("endpoint") or obj.get("url")
        if ep:
            urls.add(ep)
    return sorted(urls)


def run_naabu(host: str, timeout: int = DEFAULT_TIMEOUT) -> list[int]:
    """يفحص المنافذ (connect scan لتجنّب صلاحيات raw socket)."""
    host = safe_arg(host)
    _require("naabu")
    proc = subprocess.run(
        ["naabu", "-host", host, "-silent", "-json", "-scan-type", "c", "-top-ports", "1000"],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    ports: set[int] = set()
    for item in _jsonl(proc.stdout):
        try:
            ports.add(int(item["port"]))
        except (KeyError, ValueError, TypeError):
            continue
    _check("naabu", proc, bool(ports))
    return sorted(ports)
