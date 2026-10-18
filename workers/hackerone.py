"""عميل HackerOne — جلب التقارير السابقة وإرسال مسودة (بموافقة صريحة).

الجالب (fetcher) يُحقَن للاختبار. الإرسال يتطلب مفاتيح API وموافقة صريحة من
المستخدم في كل مرة — لا إرسال آلي إطلاقًا.
"""

from __future__ import annotations

import base64
import json
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from api.config import settings


@dataclass
class PriorReport:
    title: str
    asset: str
    source: str  # "me" | "hacktivity"


def _auth_header() -> str:
    user, token = settings.hackerone_api_username, settings.hackerone_api_token
    return "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()


def _get_json(url: str) -> dict:
    req = urllib.request.Request(
        url, headers={"Authorization": _auth_header(), "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
        return json.loads(resp.read())


def _default_prior_fetch(handle: str) -> list[dict]:
    if not (settings.hackerone_api_username and settings.hackerone_api_token):
        return []
    out: list[dict] = []
    try:
        for r in _get_json("https://api.hackerone.com/v1/hackers/me/reports").get("data", []):
            a = r.get("attributes", {})
            out.append({"title": a.get("title", ""), "asset": a.get("asset_identifier", ""), "source": "me"})
    except Exception:
        pass
    try:
        url = f"https://api.hackerone.com/v1/hackers/hacktivity?queryString=team:{handle}"
        for r in _get_json(url).get("data", []):
            a = r.get("attributes", {})
            out.append({"title": a.get("title", ""), "asset": a.get("asset_identifier", ""), "source": "hacktivity"})
    except Exception:
        pass
    return out


def fetch_prior_reports(
    handle: str, fetcher: Callable[[str], list[dict]] | None = None
) -> list[PriorReport]:
    raw = (fetcher or _default_prior_fetch)(handle)
    return [PriorReport(title=r.get("title", ""), asset=r.get("asset", ""), source=r.get("source", "")) for r in raw]


def submit_report(title: str, body: str, program_handle: str, severity: str | None = None) -> dict:
    """يرسل تقريرًا إلى HackerOne. يتطلب مفاتيح API (الموافقة تُفرَض في الـ API)."""
    if not (settings.hackerone_api_username and settings.hackerone_api_token):
        raise RuntimeError("مفاتيح HackerOne غير مهيّأة")

    attributes = {"team_handle": program_handle, "title": title, "vulnerability_information": body}
    if severity:
        attributes["severity_rating"] = severity
    payload = {"data": {"type": "report", "attributes": attributes}}

    req = urllib.request.Request(
        "https://api.hackerone.com/v1/hackers/reports",
        data=json.dumps(payload).encode(),
        headers={"Authorization": _auth_header(), "Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        data = json.loads(resp.read())
    rid = (data.get("data") or {}).get("id")
    return {"id": rid, "url": f"https://hackerone.com/reports/{rid}" if rid else None}
