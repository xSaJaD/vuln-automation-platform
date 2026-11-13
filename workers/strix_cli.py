"""غلاف strix CLI الحقيقي — يعمل داخل حاوية الـ worker.

Strix يشغّل كل فحص في sandbox خاص به (يحتاج وصولًا لـ Docker). المفاتيح
(STRIX_LLM, LLM_API_KEY) تُقرأ من البيئة. أسماء بعض الفلاغات قد تختلف حسب
إصدار strix — راجع `strix --help` عند الحاجة.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

from workers.strix_logic import StrixResult


def _parse_output(out_dir: str) -> list[dict]:
    """يجمع الثغرات من ملفات JSON التي يكتبها strix في مجلد التشغيل."""
    vulns: list[dict] = []
    for root, _dirs, files in os.walk(out_dir):
        for name in files:
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    data = json.load(fh)
            except (json.JSONDecodeError, OSError):
                continue
            vulns.extend(_extract(data))
    return vulns


_NAME_KEYS = ("title", "type", "name")
_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def _is_vuln(item) -> bool:
    """عنصر يُعدّ ثغرة فقط إن كان له اسم وخطورة صالحة.

    يمنع تحويل ملفات الحالة/الإعدادات (أي dict فيه title) إلى findings وهمية.
    """
    if not isinstance(item, dict):
        return False
    if not any(isinstance(item.get(k), str) and item[k].strip() for k in _NAME_KEYS):
        return False
    return str(item.get("severity") or "").strip().lower() in _SEVERITIES


def _extract(data) -> list[dict]:
    if isinstance(data, list):
        return [v for v in data if _is_vuln(v)]
    if isinstance(data, dict):
        for key in ("vulnerabilities", "findings", "results"):
            if isinstance(data.get(key), list):
                return [v for v in data[key] if _is_vuln(v)]
        if _is_vuln(data):
            return [data]
    return []


def run_strix_cli(
    target: str,
    instruction: str | None = None,
    *,
    output_root: str = "strix_runs",
    budget: str | None = None,
    timeout: int = 1800,
) -> StrixResult:
    from workers.tools import safe_arg

    target = safe_arg(target)  # يمنع Argument Injection في strix --target
    if shutil.which("strix") is None:
        raise RuntimeError("strix غير مثبّت في بيئة التشغيل (worker)")

    run_name = f"strix-{int(time.time())}"
    out_dir = os.path.join(output_root, run_name)
    os.makedirs(out_dir, exist_ok=True)

    cmd = ["strix", "--target", target, "-n"]  # -n = غير تفاعلي
    if instruction:
        cmd += ["--instruction", instruction]
    if budget:
        cmd += ["--max-cost", str(budget)]  # حارس تكلفة LLM (اسم الفلاغ قد يختلف)

    try:
        proc = subprocess.run(
            cmd,
            cwd=out_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=os.environ.copy(),
        )
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        return StrixResult(exit_code=124, vulnerabilities=[], run_dir=out_dir)

    return StrixResult(exit_code=exit_code, vulnerabilities=_parse_output(out_dir), run_dir=out_dir)
