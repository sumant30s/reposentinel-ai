import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low"]


class FindingData(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    confidence: Literal["high", "medium", "low"] = "medium"
    file: str
    line: int | None = None
    language: str = "Python"
    description: str
    remediation: str
    evidence: str = "[Source omitted to avoid disclosing credentials]"
    cwe: list[str] = Field(default_factory=list)
    owasp: str | None = None
    references: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=list)
    advisory_id: str | None = None
    advisory_aliases: list[str] = Field(default_factory=list)
    cvss: list[dict] = Field(default_factory=list)
    priority: Severity = "medium"
    priority_score: int = 0
    priority_reason: str = ""
    source_severity: str | None = None
    fingerprint: str = ""
    suppressed: bool = False

    def identify(self) -> "FindingData":
        # No raw source or secret is hashed. Line-based fingerprints move when lines move.
        value = f"{self.rule_id}|{self.file}|{self.line}|{self.advisory_id or ''}"
        self.fingerprint = hashlib.sha256(value.encode()).hexdigest()
        return self


class ScanRequest(BaseModel):
    source: Literal["demo", "git"] = "demo"
    url: str | None = Field(None, max_length=300)
    authorized: bool = False


class Preferences(BaseModel):
    fail_on: Severity = "high"
    exposure: Literal["internal", "internet"] = "internal"
    critical_asset: bool = False
    exclusions: list[str] = Field(default_factory=list, max_length=30)


class ExplainRequest(BaseModel):
    use_ai: bool = False
    consent_external: bool = False


class Explanation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(max_length=4000)
    impact: str = Field(max_length=4000)
    concept: str = Field(max_length=4000)
    safer_pattern: str = Field(max_length=6000)
    proposed_change: str = Field(max_length=8000)
    false_positive: str = Field(max_length=4000)
    provider: str = "local-guidance"
    warning: str | None = None


class SuppressRequest(BaseModel):
    reason: str = Field(min_length=12, max_length=1000)


class ScanView(BaseModel):
    id: str
    repository_id: str
    name: str
    status: str
    created_at: str
    started_at: str | None
    finished_at: str | None
    summary: dict
    error: str | None
