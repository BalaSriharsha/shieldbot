"""Ruff Python quality and security scanner."""

from __future__ import annotations

import json
import shutil

from shieldbot.models import Finding, FindingCategory, Severity, ScanResult
from shieldbot.scanners.base import BaseScanner, infer_category_from_rule_id

# Ruff rule prefixes mapped to severity
_RUFF_SEVERITY = {
    "S": Severity.MEDIUM,    # flake8-bandit security rules
    "E": Severity.LOW,
    "W": Severity.LOW,
    "F": Severity.LOW,
    "B": Severity.MEDIUM,    # flake8-bugbear
    "SIM": Severity.LOW,
    "UP": Severity.INFO,
    "C": Severity.LOW,
    "N": Severity.INFO,
    "ANN": Severity.INFO,
}

_SECURITY_PREFIXES = {"S", "B"}


class RuffScanner(BaseScanner):
    name = "ruff"

    def is_available(self) -> bool:
        return shutil.which("ruff") is not None

    async def run(self, repo_path: str, **kwargs) -> ScanResult:
        languages: list[str] = kwargs.get("languages", [])
        if languages and "python" not in [l.lower() for l in languages]:
            return ScanResult(scanner=self.name, success=True, findings=[])

        if not self.is_available():
            return ScanResult(scanner=self.name, success=True, findings=[], error_message="ruff not found (optional)")

        cmd = [
            "ruff",
            "check",
            "--select", "S,E,W,F,B,SIM,UP",
            "--output-format", "json",
            "--no-cache",
            repo_path,
        ]

        stdout, stderr, rc = await self._run_subprocess(cmd, timeout=60)

        if not stdout.strip():
            return ScanResult(scanner=self.name, success=True, findings=[])

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            return ScanResult(scanner=self.name, success=True, findings=[])

        findings = self._normalize(raw, repo_path)
        return ScanResult(scanner=self.name, success=True, findings=findings)

    def _normalize(self, raw: list, repo_path: str) -> list[Finding]:
        findings: list[Finding] = []
        prefix = repo_path.rstrip("/") + "/"

        for issue in raw:
            rule_id: str = issue.get("code", "unknown")
            prefix_code = "".join(c for c in rule_id if not c.isdigit())

            severity = _RUFF_SEVERITY.get(prefix_code, Severity.INFO)
            category = (
                infer_category_from_rule_id(rule_id)
                if prefix_code in _SECURITY_PREFIXES
                else FindingCategory.CODE_QUALITY
            )

            file_path = issue.get("filename", "")
            if file_path.startswith(prefix):
                file_path = file_path[len(prefix):]

            loc = issue.get("location", {})
            end_loc = issue.get("end_location", {})

            findings.append(Finding(
                scanner=self.name,
                rule_id=rule_id,
                title=issue.get("message", rule_id),
                description=issue.get("message", ""),
                severity=severity,
                category=category,
                file_path=file_path,
                line_start=loc.get("row", 0),
                line_end=end_loc.get("row"),
                column=loc.get("column"),
                references=[issue.get("url", "")] if issue.get("url") else [],
                confidence="medium",
            ))
        return findings
