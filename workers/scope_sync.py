"""مزامنة النطاق من HackerOne ومطابقته محليًا.

reconcile_scope: يضيف الأصول الجديدة، يحدّث الحالية، و**يُعطّل أي أصل اختفى من
النطاق البعيد** — فيتوقف فحصه تلقائيًا (rules_for يستبعد غير النشط).
الجالب (fetcher) يُحقَن حتى يُختبَر بلا شبكة.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session

from api.config import settings
from api.models.audit import AuditLog
from api.models.program import AssetKind, Program, ScopeAsset

_VALID_KINDS = {k.value for k in AssetKind}


@dataclass
class RemoteAsset:
    kind: str
    identifier: str
    in_scope: bool = True
    max_severity: str | None = None
    instruction: str | None = None


def _map_h1(raw: dict) -> RemoteAsset:
    a = raw.get("attributes", raw)
    t = (a.get("asset_type") or "").upper()
    kind = {
        "WILDCARD": "wildcard",
        "CIDR": "cidr",
        "IP_ADDRESS": "ip",
        "URL": "domain",
        "SOURCE_CODE": "repo",
    }.get(t, "domain")
    ident = (a.get("asset_identifier") or "").strip()
    if kind == "domain" and ident.startswith("*."):
        kind = "wildcard"
    if kind not in _VALID_KINDS:
        kind = "domain"
    return RemoteAsset(
        kind=kind,
        identifier=ident,
        in_scope=bool(a.get("eligible_for_submission", True)),
        max_severity=a.get("max_severity"),
        instruction=a.get("instruction"),
    )


def _default_fetch(handle: str) -> list[dict]:
    import base64
    import json
    import urllib.request

    user, token = settings.hackerone_api_username, settings.hackerone_api_token
    if not (user and token):
        return []
    url = f"https://api.hackerone.com/v1/programs/{handle}/structured_scopes"
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    req = urllib.request.Request(
        url, headers={"Authorization": "Basic " + auth, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            return json.loads(resp.read()).get("data", [])
    except Exception:
        return []


def fetch_structured_scopes(
    handle: str, fetcher: Callable[[str], list[dict]] | None = None
) -> list[RemoteAsset]:
    raw = (fetcher or _default_fetch)(handle)
    return [_map_h1(item) for item in raw if item]


def reconcile_scope(
    db: Session, program: Program, remote: list[RemoteAsset], actor: str = "scope-sync"
) -> dict:
    local = {(a.kind.value, a.identifier.lower()): a for a in program.scope_assets}
    remote_keys: set[tuple[str, str]] = set()
    added = updated = deactivated = 0

    for r in remote:
        key = (r.kind, r.identifier.lower())
        remote_keys.add(key)
        asset = local.get(key)
        if asset is None:
            # append للعلاقة حتى يبقى الكائن في الذاكرة متّسقًا (لا نعتمد على refresh).
            program.scope_assets.append(
                ScopeAsset(
                    kind=AssetKind(r.kind),
                    identifier=r.identifier,
                    in_scope=r.in_scope,
                    max_severity=r.max_severity,
                    instruction=r.instruction,
                    active=True,
                )
            )
            added += 1
        else:
            asset.in_scope = r.in_scope
            asset.max_severity = r.max_severity
            asset.instruction = r.instruction
            asset.active = True
            updated += 1

    # تعطيل الأصول التي اختفت من النطاق البعيد.
    for key, asset in local.items():
        if key not in remote_keys and asset.active is not False:
            asset.active = False
            deactivated += 1
            db.add(
                AuditLog(
                    action="scope_deactivate",
                    target_value=asset.identifier,
                    program_id=program.id,
                    decision="deny",
                    reason="أُزيل من نطاق البرنامج — تعطّل الفحص",
                    actor=actor,
                )
            )

    db.commit()
    return {"added": added, "updated": updated, "deactivated": deactivated}
