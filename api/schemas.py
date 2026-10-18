"""مخططات Pydantic للمدخلات والمخرجات."""

from pydantic import BaseModel, ConfigDict


class ProgramIn(BaseModel):
    name: str
    handle: str
    platform: str = "hackerone"
    policy_url: str | None = None
    roe_notes: str | None = None
    rate_limit_per_min: int | None = None


class ProgramOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    handle: str
    platform: str
    policy_url: str | None
    active: bool
    roe_notes: str | None
    rate_limit_per_min: int | None


class ScopeAssetIn(BaseModel):
    kind: str          # domain | wildcard | ip | cidr | url | repo
    identifier: str
    in_scope: bool = True
    max_severity: str | None = None
    notes: str | None = None


class ScopeAssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    kind: str
    identifier: str
    in_scope: bool
    max_severity: str | None
    notes: str | None
    instruction: str | None
    active: bool


class HostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    program_id: int
    hostname: str
    ip: str | None
    is_live: bool
    http_status: int | None
    title: str | None
    tech: str | None
    open_ports: str | None
    source: str
    in_scope: bool


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_run_id: int
    host: str
    endpoint: str | None
    vuln_type: str
    severity: str
    evidence: str | None
    source_tool: str
    confirmed_by_strix: bool
    status: str


class CorrelatedFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    program_id: int
    host: str
    endpoint: str | None
    vuln_type: str
    severity: str
    sources: str
    confirmed_by_strix: bool
    evidence: str | None
    finding_count: int
    status: str
    cvss_score: float | None
    cvss_vector: str | None
    cvss_manual: bool
    likely_duplicate: bool
    duplicate_ref: str | None
    submitted_ref: str | None


class TargetIn(BaseModel):
    program_id: int
    value: str


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    program_id: int
    value: str
    status: str
    decision_reason: str | None
