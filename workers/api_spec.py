"""اكتشاف مواصفات الـ API (OpenAPI/Swagger + GraphQL introspection) — نقي.

ملف OpenAPI واحد يعطي كل الـ endpoints والمعاملات بدقّة كاملة — أفضل من أي regex
على JS. و GraphQL introspection يكشف كامل المخطّط. الجالب محقون للاختبار.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin

from api.services.scope_matching import ScopeRule, evaluate, host_of

OPENAPI_PATHS = (
    "/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/api/openapi.json", "/api/swagger.json", "/api-docs", "/swagger/v1/swagger.json",
    "/api/v1/openapi.json", "/.well-known/openapi.json",
)
GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")

INTROSPECTION_QUERY = (
    '{"query":"query{__schema{queryType{name} types{name kind '
    'fields{name args{name}}}}}"}'
)


@dataclass
class ApiEndpoint:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)


@dataclass
class ApiSpecResult:
    endpoints: list[ApiEndpoint] = field(default_factory=list)
    graphql_introspection: bool = False
    spec_url: str | None = None
    graphql_url: str | None = None


@dataclass
class Fetched:
    status_code: int
    body: str = ""


# fetch(url) -> Fetched ؛  post(url, body) -> Fetched
FetchFn = Callable[[str], Fetched]
PostFn = Callable[[str, str], Fetched]


def parse_openapi(raw: str, base_url: str) -> list[ApiEndpoint]:
    """يستخرج (method, path, params) من وثيقة OpenAPI/Swagger."""
    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(doc, dict):
        return []

    # basePath (Swagger 2) أو servers[0].url (OpenAPI 3).
    base = ""
    if isinstance(doc.get("servers"), list) and doc["servers"]:
        base = (doc["servers"][0] or {}).get("url", "") if isinstance(doc["servers"][0], dict) else ""
    base = base or doc.get("basePath", "") or ""

    out: list[ApiEndpoint] = []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch", "head", "options"):
                continue
            params = []
            if isinstance(op, dict):
                for p in op.get("parameters") or []:
                    if isinstance(p, dict) and p.get("name"):
                        params.append(str(p["name"]))
            full = urljoin(base_url, (base.rstrip("/") + "/" + path.lstrip("/")) if base else path)
            out.append(ApiEndpoint(url=full, method=method.upper(), params=params))
    return out


def discover_api_spec(
    seed: str, fetch: FetchFn, post: PostFn, rules: list[ScopeRule]
) -> ApiSpecResult:
    """يجرّب مسارات OpenAPI المعروفة + GraphQL introspection (كلها ضمن النطاق)."""
    base = seed if "://" in seed else f"https://{seed}"
    host = host_of(base)
    result = ApiSpecResult()

    for path in OPENAPI_PATHS:
        url = urljoin(base, path)
        if host_of(url) != host or not evaluate(url, rules).allowed:
            continue
        try:
            res = fetch(url)
        except Exception:
            continue
        if res.status_code == 200 and res.body:
            eps = parse_openapi(res.body, url)
            if eps:
                result.endpoints = eps
                result.spec_url = url
                break

    for path in GRAPHQL_PATHS:
        url = urljoin(base, path)
        if host_of(url) != host or not evaluate(url, rules).allowed:
            continue
        try:
            res = post(url, INTROSPECTION_QUERY)
        except Exception:
            continue
        if res.status_code == 200 and "__schema" in (res.body or ""):
            result.graphql_introspection = True   # introspection مفتوح = تسريب مخطّط
            result.graphql_url = url
            break

    return result
