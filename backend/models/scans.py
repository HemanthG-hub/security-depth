from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
RiskLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class ScanCreate(BaseModel):
    code: str = Field(min_length=1, max_length=120_000)
    language: str = Field(default="auto", max_length=40)
    file_name: str | None = Field(default=None, max_length=160)
    ai_mode: Literal["MOCK_AI", "LIVE_AI"] = "MOCK_AI"


class GitHubScanCreate(BaseModel):
    repository_url: str = Field(min_length=1, max_length=500)
    ai_mode: Literal["MOCK_AI", "LIVE_AI"] = "MOCK_AI"


class Vulnerability(BaseModel):
    id: str
    title: str
    severity: Severity
    cwe: str
    owasp_category: str
    line: int
    evidence: str
    explanation: str
    recommendation: str
    secure_fix: str
    exploitability: str
    source: Literal["DETERMINISTIC", "AI_ASSISTED"] = "DETERMINISTIC"
    file_name: str | None = None


class ScoreBreakdown(BaseModel):
    severity_impact: int
    sensitive_data_exposure: int
    repeated_patterns: int
    complexity: int
    dependency_risk: int
    total: int


class ScanResult(BaseModel):
    id: str
    language: str
    file_name: str | None = None
    source_code: str
    security_score: int
    risk_level: RiskLevel
    vulnerabilities: list[Vulnerability]
    summary: str
    security_debt: str
    breakdown: ScoreBreakdown
    ai_mode: Literal["MOCK_AI", "LIVE_AI"] = "MOCK_AI"
    ai_explanation: str
    line_count: int
    created_at: datetime
    repository_url: str | None = None
    files_scanned: int = 1
    storage_mode: Literal["PERSISTED", "EPHEMERAL"] = "PERSISTED"


class ScanSummary(BaseModel):
    id: str
    language: str
    file_name: str | None = None
    security_score: int
    risk_level: RiskLevel
    vulnerability_count: int
    created_at: datetime
