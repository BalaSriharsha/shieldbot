"""npm audit: Node.js dependency CVE scanner."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from shieldbot.models import Finding, FindingCategory, Severity, ScanResult
from shieldbot.scanners.base import BaseScanner


_NPM_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class NpmAuditScanner(BaseScanner):
    name = "npm-audit"

    def is_available(self) -> bool:
        return shutil.which("npm") is not None

    async def run(self, repo_path: str, **kwargs) -> ScanResult:
        # Only run if package.json exists
        pkg_files = list(Path(repo_path).rglob("package.json"))
        # Exclude node_modules
        pkg_files = [p for p in pkg_files if "node_modules" not in str(p)]

        if not pkg_files:
            return ScanResult(scanner=self.name, success=True, findings=[])

        if not self.is_available():
            return self._make_error_result(
                "npm not found on PATH. Install Node.js to enable npm audit."
            )

        all_findings: list[Finding] = []
        for pkg_file in pkg_files:
            pkg_dir = str(pkg_file.parent)
            findings = await self._audit_dir(pkg_dir, repo_path)
            all_findings.extend(findings)

        return ScanResult(scanner=self.name, success=True, findings=all_findings)

    async def _audit_dir(self, pkg_dir: str, repo_path: str) -> list[Finding]:
        cmd = ["npm", "audit", "--json"]
        stdout, stderr, rc = await self._run_subprocess(cmd, cwd=pkg_dir, timeout=120)

        if not stdout.strip():
            return []

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        return self._normalize(raw, pkg_dir, repo_path)

    def _normalize(self, raw: dict, pkg_dir: str, repo_path: str) -> list[Finding]:
        findings: list[Finding] = []
        prefix = repo_path.rstrip("/") + "/"
        rel_dir = pkg_dir[len(prefix):] if pkg_dir.startswith(prefix) else pkg_dir
        pkg_json_path = f"{rel_dir}/package.json".lstrip("/")

        # npm audit v2+ format
        vulnerabilities = raw.get("vulnerabilities", {})
        for pkg_name, vuln_data in vulnerabilities.items():
            severity_raw = vuln_data.get("severity", "moderate")
            severity = _NPM_SEVERITY_MAP.get(severity_raw, Severity.MEDIUM)

            # Each vulnerability may contain multiple CVEs via 'via'
            via = vuln_data.get("via", [])
            cve_ids: list[str] = []
            descriptions: list[str] = []
            urls: list[str] = []

            for v in via:
                if isinstance(v, dict):
                    vuln_id = v.get("url", "")
                    title = v.get("title", "")
                    if title:
                        descriptions.append(title)
                    if vuln_id:
                        urls.append(vuln_id)
                    # Extract CVE from the source field
                    source = v.get("source", 0)
                    cve = v.get("cve", "")
                    if cve:
                        cve_ids.append(cve)

            fix_available = vuln_data.get("fixAvailable", False)
            fix_note = ""
            if isinstance(fix_available, dict):
                fix_version = fix_available.get("version", "")
                fix_name = fix_available.get("name", pkg_name)
                fix_note = f" Fix: upgrade {fix_name} to {fix_version}."
            elif fix_available is True:
                fix_note = " Fix available via `npm audit fix`."

            findings.append(Finding(
                scanner=self.name,
                rule_id=f"npm-audit/{pkg_name}",
                title=f"{pkg_name} ({severity_raw}) - {', '.join(descriptions) or 'vulnerability'}",
                description="; ".join(descriptions) or f"Vulnerability in npm package {pkg_name}",
                severity=severity,
                category=FindingCategory.DEPENDENCY_CVE,
                file_path=pkg_json_path,
                line_start=0,
                cve_id=cve_ids[0] if cve_ids else None,
                remediation=f"Upgrade or remove vulnerable package {pkg_name}.{fix_note}",
                references=urls,
                confidence="high",
            ))

        return findings
