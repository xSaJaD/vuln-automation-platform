"""مخططات Pydantic للمدخلات والمخرجات."""

from pydantic import BaseModel, ConfigDict


class ProgramIn(BaseModel):
    name: str
    handle: str
    platform: str = "hackerone"
    policy_url: str | None = None


class ProgramOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    handle: str
    platform: str
    policy_url: str | None
    active: bool


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
