"""pip-audit: Python dependency CVE scanner."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from shieldbot.models import Finding, FindingCategory, Severity, ScanResult
from shieldbot.scanners.base import BaseScanner


_PIP_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class PipAuditScanner(BaseScanner):
    name = "pip-audit"

    def is_available(self) -> bool:
        return shutil.which("pip-audit") is not None or shutil.which("safety") is not None

    async def run(self, repo_path: str, **kwargs) -> ScanResult:
        # Only run if Python dependency files exist
        req_files = self._find_requirements_files(repo_path)
        if not req_files:
            return ScanResult(scanner=self.name, success=True, findings=[])

        if not self.is_available():
            return self._make_error_result(
                "pip-audit not found. Install: pip install pip-audit"
            )

        if shutil.which("pip-audit"):
            return await self._run_pip_audit(repo_path, req_files)
        else:
            return await self._run_safety(repo_path, req_files)

    def _find_requirements_files(self, repo_path: str) -> list[str]:
        found = []
        for pattern in ["requirements*.txt", "requirements/*.txt", "pyproject.toml", "setup.cfg"]:
            for p in Path(repo_path).rglob(pattern):
                found.append(str(p))
        return found

    async def _run_pip_audit(self, repo_path: str, req_files: list[str]) -> ScanResult:
        all_findings: list[Finding] = []

        for req_file in req_files:
            if "pyproject.toml" in req_file or "setup.cfg" in req_file:
                cmd = ["pip-audit", "--format", "json", "--project-dir", os.path.dirname(req_file)]
            else:
                cmd = ["pip-audit", "--format", "json", "-r", req_file]

            stdout, stderr, rc = await self._run_subprocess(cmd, timeout=120)

            if not stdout.strip():
                continue

            try:
                raw = json.loads(stdout)
            except json.JSONDecodeError:
                continue

            deps = raw.get("dependencies", []) if isinstance(raw, dict) else raw
            all_findings.extend(self._normalize_pip_audit(deps, req_file, repo_path))

        return ScanResult(scanner=self.name, success=True, findings=all_findings)

    def _normalize_pip_audit(self, deps: list, req_file: str, repo_path: str) -> list[Finding]:
        findings: list[Finding] = []
        prefix = repo_path.rstrip("/") + "/"
        rel_req = req_file[len(prefix):] if req_file.startswith(prefix) else req_file

        for dep in deps:
            for vuln in dep.get("vulns", []):
                aliases = vuln.get("aliases", [])
                cve_ids = [a for a in aliases if a.startswith("CVE-")]
                cve_id = cve_ids[0] if cve_ids else None

                severity_raw = vuln.get("fix_versions_severity", "MEDIUM")
                severity = _PIP_SEVERITY_MAP.get(severity_raw.upper(), Severity.MEDIUM)

                fix_versions = vuln.get("fix_versions", [])
                fix_str = f" Fix: upgrade to {', '.join(fix_versions)}." if fix_versions else ""

                findings.append(Finding(
                    scanner=self.name,
                    rule_id=f"pip-audit/{vuln.get('id', 'unknown')}",
                    title=f"{dep.get('name')} {dep.get('version')} - {vuln.get('id')}",
                    description=vuln.get("description", f"Vulnerability in {dep.get('name')}"),
                    severity=severity,
                    category=FindingCategory.DEPENDENCY_CVE,
                    file_path=rel_req,
                    line_start=0,
                    cve_id=cve_id,
                    cwe_id=None,
                    remediation=f"Upgrade {dep.get('name')} from {dep.get('version')}.{fix_str}",
                    references=vuln.get("aliases", []),
                    confidence="high",
                ))
        return findings

    async def _run_safety(self, repo_path: str, req_files: list[str]) -> ScanResult:
        """Fallback to safety check if pip-audit is unavailable."""
        req_file = req_files[0]
        cmd = ["safety", "check", "-r", req_file, "--json"]
        stdout, stderr, rc = await self._run_subprocess(cmd, timeout=120)

        if not stdout.strip():
            return ScanResult(scanner=self.name, success=True, findings=[])

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            return ScanResult(scanner=self.name, success=True, findings=[])

        findings = self._normalize_safety(raw, req_file, repo_path)
        return ScanResult(scanner=self.name, success=True, findings=findings)

    def _normalize_safety(self, raw: list, req_file: str, repo_path: str) -> list[Finding]:
        findings: list[Finding] = []
        prefix = repo_path.rstrip("/") + "/"
        rel_req = req_file[len(prefix):] if req_file.startswith(prefix) else req_file

        for vuln in (raw or []):
            name, specs, version, advisory, vuln_id = (vuln + [None] * 5)[:5]
            findings.append(Finding(
                scanner="safety",
                rule_id=f"safety/{vuln_id or 'unknown'}",
                title=f"{name} {version} - {vuln_id}",
                description=advisory or f"Vulnerability in {name}",
                severity=Severity.HIGH,
                category=FindingCategory.DEPENDENCY_CVE,
                file_path=rel_req,
                line_start=0,
                remediation=f"Upgrade {name} to a patched version.",
                confidence="high",
            ))
        return findings
