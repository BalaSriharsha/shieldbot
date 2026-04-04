"""Semgrep SAST scanner - 5,000+ registry rules."""

from __future__ import annotations

import json
import shutil
import time
from typing import Any

from shieldbot.config import (
    SEMGREP_ALWAYS_RULESETS,
    SEMGREP_JOBS,
    SEMGREP_LANGUAGE_RULESETS,
    SEMGREP_MAX_MEMORY_MB,
    SEMGREP_OVERALL_TIMEOUT,
    SEMGREP_TIMEOUT_PER_FILE,
)
from shieldbot.models import Finding, FindingCategory, Severity, ScanResult
from shieldbot.scanners.base import BaseScanner, infer_category_from_rule_id


_SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "CRITICAL": Severity.CRITICAL,
    # Semgrep sometimes returns lowercase
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "critical": Severity.CRITICAL,
}


class SemgrepScanner(BaseScanner):
    name = "semgrep"

    def __init__(self, rulesets: list[str] | None = None):
        self._rulesets = rulesets  # If None, auto-select based on languages kwarg

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    async def run(self, repo_path: str, **kwargs) -> ScanResult:
        if not self.is_available():
            return self._make_error_result("semgrep not found on PATH. Install: pip install semgrep")

        languages: list[str] = kwargs.get("languages", [])
        rulesets = self._rulesets or self._select_rulesets(languages)

        config_args: list[str] = []
        for rs in rulesets:
            config_args.extend(["--config", rs])

        cmd = [
            "semgrep",
            "scan",
            "--json",
            "--metrics=off",
            "--no-git-ignore",
            "--timeout", str(SEMGREP_TIMEOUT_PER_FILE),
            "--max-memory", str(SEMGREP_MAX_MEMORY_MB),
            "--jobs", str(SEMGREP_JOBS),
            *config_args,
            repo_path,
        ]

        stdout, stderr, rc = await self._run_subprocess(
            cmd, timeout=SEMGREP_OVERALL_TIMEOUT
        )

        # semgrep exits non-zero when findings exist; that's expected
        if not stdout.strip():
            return self._make_error_result(f"semgrep produced no output. stderr: {stderr[:500]}")

        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError as e:
            return self._make_error_result(f"Failed to parse semgrep JSON: {e}. stderr: {stderr[:300]}")

        findings = self._normalize(raw, repo_path)
        files_scanned = len(raw.get("paths", {}).get("scanned", []))

        return ScanResult(
            scanner=self.name,
            success=True,
            findings=findings,
            raw_output={"errors": raw.get("errors", [])},
            files_scanned=files_scanned,
        )

    def _select_rulesets(self, languages: list[str]) -> list[str]:
        rulesets = list(SEMGREP_ALWAYS_RULESETS)
        seen = set(rulesets)
        for lang in languages:
            for rs in SEMGREP_LANGUAGE_RULESETS.get(lang.lower(), []):
                if rs not in seen:
                    rulesets.append(rs)
                    seen.add(rs)
        # Fallback: at minimum run security-audit
        if "p/security-audit" not in seen:
            rulesets.append("p/security-audit")
        return rulesets

    def _normalize(self, raw: dict[str, Any], repo_path: str) -> list[Finding]:
        findings: list[Finding] = []
        prefix = repo_path.rstrip("/") + "/"

        for result in raw.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            severity_raw = extra.get("severity", "WARNING")
            severity = _SEMGREP_SEVERITY_MAP.get(severity_raw, Severity.MEDIUM)

            # Upgrade to CRITICAL based on metadata impact
            if metadata.get("impact") == "CRITICAL" or metadata.get("severity") == "CRITICAL":
                severity = Severity.CRITICAL

            rule_id: str = result.get("check_id", "unknown")
            file_path: str = result.get("path", "")
            if file_path.startswith(prefix):
                file_path = file_path[len(prefix):]

            # Code snippet: strip to MAX_SNIPPET_LINES
            lines_raw: str = extra.get("lines", "")
            lines = lines_raw.split("\n")
            snippet = "\n".join(lines[:10]) if lines else None

            # CWE / OWASP from metadata
            cwe_list = metadata.get("cwe", [])
            cwe_id = cwe_list[0] if isinstance(cwe_list, list) and cwe_list else (cwe_list if isinstance(cwe_list, str) else None)
            owasp_list = metadata.get("owasp", [])
            owasp = owasp_list[0] if isinstance(owasp_list, list) and owasp_list else (owasp_list if isinstance(owasp_list, str) else None)

            findings.append(Finding(
                scanner=self.name,
                rule_id=rule_id,
                title=extra.get("message", rule_id)[:200],
                description=extra.get("message", ""),
                severity=severity,
                category=infer_category_from_rule_id(rule_id),
                file_path=file_path,
                line_start=result.get("start", {}).get("line", 0),
                line_end=result.get("end", {}).get("line"),
                column=result.get("start", {}).get("col"),
                code_snippet=snippet,
                cwe_id=cwe_id,
                owasp_category=owasp,
                references=metadata.get("references", []),
                confidence=metadata.get("confidence", "medium").lower(),
            ))
        return findings
