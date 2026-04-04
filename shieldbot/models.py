"""Pydantic data models for shieldbot security findings and reports."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class FindingCategory(str, Enum):
    INJECTION = "injection"
    SECRETS = "secrets"
    CRYPTOGRAPHY = "cryptography"
    AUTHENTICATION = "authentication"
    ACCESS_CONTROL = "access_control"
    DEPENDENCY_CVE = "dependency_cve"
    DESERIALIZATION = "deserialization"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    SSRF = "ssrf"
    CODE_QUALITY = "code_quality"
    MISCONFIGURATION = "misconfiguration"
    OTHER = "other"


class Finding(BaseModel):
    id: str = ""
    scanner: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: FindingCategory
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    column: Optional[int] = None
    code_snippet: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    confidence: str = "medium"
    is_false_positive: bool = False
    duplicate_of: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            raw = f"{self.rule_id}:{self.file_path}:{self.line_start}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:16]


class ScanResult(BaseModel):
    scanner: str
    success: bool
    findings: List[Finding] = Field(default_factory=list)
    raw_output: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    duration_seconds: float = 0.0
    files_scanned: int = 0


class ClaudeAnalysis(BaseModel):
    executive_summary: str
    risk_score: int = Field(ge=0, le=100)
    risk_label: str
    prioritized_findings: List[str] = Field(default_factory=list)
    false_positive_ids: List[str] = Field(default_factory=list)
    attack_narrative: Optional[str] = None
    top_remediations: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_focus: str = ""


class SecurityReport(BaseModel):
    report_id: str
    repo_path: str
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)
    scan_duration_seconds: float = 0.0
    languages_detected: List[str] = Field(default_factory=list)
    scanners_run: List[str] = Field(default_factory=list)
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings_by_category: Dict[str, int] = Field(default_factory=dict)
    all_findings: List[Finding] = Field(default_factory=list)
    scan_results: List[ScanResult] = Field(default_factory=list)
    claude_analysis: Optional[ClaudeAnalysis] = None
    report_version: str = "1.0.0"
