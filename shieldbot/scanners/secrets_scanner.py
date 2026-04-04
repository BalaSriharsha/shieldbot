"""Secrets scanner: detect-secrets (primary) with gitleaks fallback."""

from __future__ import annotations

import json
import shutil

from shieldbot.models import Finding, FindingCategory, Severity, ScanResult
from shieldbot.scanners.base import BaseScanner


class SecretsScanner(BaseScanner):
    """
    Uses detect-secrets if available, falls back to gitleaks.
    Always runs regardless of detected language.
    """

    name = "detect-secrets"

    def is_available(self) -> bool:
        return shutil.which("detect-secrets") is not None or shutil.which("gitleaks") is not None

    async def run(self, repo_path: str, **kwargs) -> ScanResult:
        scan_git_history: bool = kwargs.get("scan_git_history", False)

        if shutil.which("detect-secrets"):
            return await self._run_detect_secrets(repo_path)
        elif shutil.which("gitleaks"):
            return await self._run_gitleaks(repo_path, scan_git_history)
        else:
            return self._make_error_result(
                "No secrets scanner found. Install: pip install detect-secrets  "
                "OR brew install gitleaks"
            )

    # ------------------------------------------------------------------
    # detect-secrets
    # ------------------------------------------------------------------

    async def _run_detect_secrets(self, repo_path: str) -> ScanResult:
        cmd = ["detect-secrets", "scan", "--all-files", repo_path]
        stdout, stderr, rc = await self._run_subprocess(cmd, timeout=120)

        if not stdout.strip():
            return ScanResult(scanner=self.name, success=True, findings=[])

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            return self._make_error_result(f"detect-secrets parse error. stderr: {stderr[:300]}")

        findings = self._normalize_detect_secrets(raw, repo_path)
        return ScanResult(scanner=self.name, success=True, findings=findings)

    def _normalize_detect_secrets(self, raw: dict, repo_path: str) -> list[Finding]:
        findings: list[Finding] = []
        prefix = repo_path.rstrip("/") + "/"

        for file_path, secrets in raw.get("results", {}).items():
            rel_path = file_path[len(prefix):] if file_path.startswith(prefix) else file_path
            for secret in secrets:
                detector = secret.get("type", "Secret")
                line_num = secret.get("line_number", 0)
                findings.append(Finding(
                    scanner=self.name,
                    rule_id=f"detect-secrets/{detector.replace(' ', '')}",
                    title=f"Hardcoded {detector}",
                    description=f"Potential {detector} detected at line {line_num}. "
                                 "Hardcoded credentials expose systems to unauthorized access.",
                    severity=Severity.CRITICAL,
                    category=FindingCategory.SECRETS,
                    file_path=rel_path,
                    line_start=line_num,
                    cwe_id="CWE-798",
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                    remediation=(
                        "1. Immediately rotate the exposed credential.\n"
                        "2. Remove the secret from source code.\n"
                        "3. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault)."
                    ),
                    confidence="high" if secret.get("is_verified") else "medium",
                ))
        return findings

    # ------------------------------------------------------------------
    # gitleaks (fallback)
    # ------------------------------------------------------------------

    async def _run_gitleaks(self, repo_path: str, scan_history: bool) -> ScanResult:
        self.name = "gitleaks"
        cmd = [
            "gitleaks",
            "detect",
            "--source", repo_path,
            "--report-format", "json",
            "--report-path", "/dev/stdout",
            "--no-banner",
        ]
        if not scan_history:
            cmd.append("--no-git")

        stdout, stderr, rc = await self._run_subprocess(cmd, timeout=300)

        if not stdout.strip() or stdout.strip() == "null":
            return ScanResult(scanner=self.name, success=True, findings=[])

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            return ScanResult(scanner=self.name, success=True, findings=[])

        findings = self._normalize_gitleaks(raw, repo_path)
        return ScanResult(scanner=self.name, success=True, findings=findings)

    def _normalize_gitleaks(self, raw: list, repo_path: str) -> list[Finding]:
        findings: list[Finding] = []
        prefix = repo_path.rstrip("/") + "/"

        for leak in (raw or []):
            file_path = leak.get("File", "")
            if file_path.startswith(prefix):
                file_path = file_path[len(prefix):]

            rule_id = leak.get("RuleID", "gitleaks/secret")
            snippet = leak.get("Secret", "")
            # Redact most of the secret in the report
            if len(snippet) > 8:
                snippet = snippet[:4] + "***" + snippet[-4:]

            findings.append(Finding(
                scanner=self.name,
                rule_id=f"gitleaks/{rule_id}",
                title=f"Hardcoded secret: {leak.get('Description', rule_id)}",
                description=leak.get("Description", "Potential hardcoded secret detected."),
                severity=Severity.CRITICAL,
                category=FindingCategory.SECRETS,
                file_path=file_path,
                line_start=leak.get("StartLine", 0),
                line_end=leak.get("EndLine"),
                code_snippet=snippet,
                cwe_id="CWE-798",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                remediation=(
                    "1. Immediately rotate the exposed credential.\n"
                    "2. Remove the secret from source code and git history.\n"
                    "3. Use environment variables or a secrets manager."
                ),
                confidence="high",
            ))
        return findings
