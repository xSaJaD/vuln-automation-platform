"""تحقّق خارج النطاق (OOB) عبر interactsh — للثغرات العمياء (SSRF/XXE/blind RCE/SQLi).

الثغرات العمياء لا تظهر في الرد؛ تحتاج callback على خادم تتحكّم به. هذه الوحدة تعرّف
واجهة عميل OOB + دالة ربط نقية. العميل الحقيقي يُحقَن (خادم interactsh خاص بك يُفضَّل).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class Interaction:
    protocol: str          # dns | http | smtp
    unique_id: str         # المعرّف الفرعي الذي استُخدم في الحمولة
    remote_address: str = ""


class OobClient(Protocol):
    """عميل interactsh: يسجّل نطاقًا، يولّد حمولات، ويستطلع التفاعلات."""

    def domain(self) -> str: ...
    def new_payload(self) -> tuple[str, str]: ...   # (unique_id, full_host)
    def poll(self) -> list[Interaction]: ...


def correlate(expected_ids: set[str], interactions: list[Interaction]) -> set[str]:
    """يرجّع المعرّفات التي وصلها callback فعلًا (= الثغرة العمياء مؤكّدة)."""
    got = {i.unique_id for i in interactions}
    return expected_ids & got


def oob_payloads(client: OobClient, kinds=("url", "dns")) -> dict[str, str]:
    """يولّد حمولات OOB لكل نوع، مربوطة بمعرّف فريد يُستطلَع لاحقًا.

    يرجّع {unique_id: payload_value} — تُحقن في المعاملات/الحقول، ثم تُستطلَع النتيجة.
    """
    out: dict[str, str] = {}
    for _ in kinds:
        uid, host = client.new_payload()
        out[uid] = f"https://{host}/"
    return out
