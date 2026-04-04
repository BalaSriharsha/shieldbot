"""Bandit Python security linter scanner."""

from __future__ import annotations

import json
import shutil

from shieldbot.models import Finding, FindingCategory, Severity, ScanResult
from shieldbot.scanners.base import BaseScanner, infer_category_from_rule_id


_BANDIT_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_BANDIT_CONFIDENCE_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class BanditScanner(BaseScanner):
    name = "bandit"

    def is_available(self) -> bool:
        return shutil.which("bandit") is not None

    async def run(self, repo_path: str, **kwargs) -> ScanResult:
        languages: list[str] = kwargs.get("languages", [])
        if languages and "python" not in [l.lower() for l in languages]:
            return ScanResult(scanner=self.name, success=True, findings=[])

        if not self.is_available():
            return self._make_error_result("bandit not found on PATH. Install: pip install bandit")

        cmd = [
            "bandit",
            "-r", repo_path,
            "-f", "json",
            "-ll",   # low severity and above
            "--quiet",
        ]

        stdout, stderr, rc = await self._run_subprocess(cmd, timeout=120)

        if not stdout.strip():
            return ScanResult(scanner=self.name, success=True, findings=[])

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            return self._make_error_result(f"Failed to parse bandit output. stderr: {stderr[:300]}")

        findings = self._normalize(raw, repo_path)
        return ScanResult(
            scanner=self.name,
            success=True,
            findings=findings,
            files_scanned=raw.get("metrics", {}).get("_totals", {}).get("loc", 0),
        )

    def _normalize(self, raw: dict, repo_path: str) -> list[Finding]:
        findings: list[Finding] = []
        prefix = repo_path.rstrip("/") + "/"

        for issue in raw.get("results", []):
            severity_raw = issue.get("issue_severity", "MEDIUM")
            severity = _BANDIT_SEVERITY_MAP.get(severity_raw, Severity.MEDIUM)
            confidence = _BANDIT_CONFIDENCE_MAP.get(issue.get("issue_confidence", "MEDIUM"), "medium")

            file_path = issue.get("filename", "")
            if file_path.startswith(prefix):
                file_path = file_path[len(prefix):]

            rule_id = issue.get("test_id", "unknown")
            cwe_raw = issue.get("issue_cwe", {})
            cwe_id = f"CWE-{cwe_raw.get('id')}" if cwe_raw and cwe_raw.get("id") else None

            findings.append(Finding(
                scanner=self.name,
                rule_id=rule_id,
                title=issue.get("test_name", rule_id),
                description=issue.get("issue_text", ""),
                severity=severity,
                category=infer_category_from_rule_id(rule_id),
                file_path=file_path,
                line_start=issue.get("line_number", 0),
                line_end=issue.get("line_range", [None])[-1],
                code_snippet=issue.get("code", "").strip(),
                cwe_id=cwe_id,
                references=[issue.get("more_info", "")] if issue.get("more_info") else [],
                confidence=confidence,
            ))
        return findings
