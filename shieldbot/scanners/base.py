"""Abstract base scanner and shared utilities: parallel execution and deduplication."""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import time
from abc import ABC, abstractmethod
from typing import List

from shieldbot.config import SCANNER_PRIORITY
from shieldbot.models import Finding, FindingCategory, ScanResult


class BaseScanner(ABC):
    """All scanners implement this interface."""

    name: str = "base"

    @abstractmethod
    async def run(self, repo_path: str, **kwargs) -> ScanResult:
        """Execute the scanner and return normalized findings."""
        ...

    def is_available(self) -> bool:
        """Return True if the underlying tool binary is on PATH."""
        return False

    # ------------------------------------------------------------------
    # Shared subprocess helper (uses create_subprocess_exec - safe, no shell)
    # ------------------------------------------------------------------

    async def _run_subprocess(
        self,
        cmd: list[str],
        cwd: str | None = None,
        timeout: float = 120,
    ) -> tuple[str, str, int]:
        """Run cmd list via asyncio (no shell=True). Returns (stdout, stderr, returncode)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode or 0
        except asyncio.TimeoutError:
            return "", f"Scanner '{self.name}' timed out after {timeout}s", 1
        except FileNotFoundError:
            return "", f"Tool not found for scanner '{self.name}'", 127

    def _make_error_result(self, message: str) -> ScanResult:
        return ScanResult(scanner=self.name, success=False, error_message=message)


# ---------------------------------------------------------------------------
# Parallel execution
# ---------------------------------------------------------------------------


async def run_all_parallel(
    scanners: list[BaseScanner],
    repo_path: str,
    **kwargs,
) -> list[ScanResult]:
    """Run all scanners concurrently. Exceptions become error ScanResults."""

    async def _safe_run(scanner: BaseScanner) -> ScanResult:
        start = time.monotonic()
        try:
            result = await scanner.run(repo_path, **kwargs)
            result.duration_seconds = time.monotonic() - start
            return result
        except Exception as exc:  # noqa: BLE001
            return ScanResult(
                scanner=scanner.name,
                success=False,
                error_message=str(exc),
                duration_seconds=time.monotonic() - start,
            )

    return list(await asyncio.gather(*[_safe_run(s) for s in scanners]))


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _dedup_key(f: Finding) -> str:
    """Proximity-based key: same category + file + rounded line bucket."""
    bucket = (f.line_start // 3) * 3
    return f"{f.category.value}:{f.file_path}:{bucket}"


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Three-tier deduplication:
      1. Exact hash (rule_id + file + line)
      2. Proximity (same category, file, within 3 lines)
      3. Scanner priority tiebreak
    Duplicates are marked with duplicate_of rather than removed.
    """
    sorted_findings = sorted(
        findings,
        key=lambda f: SCANNER_PRIORITY.get(f.scanner, 99),
    )

    canonical: dict[str, Finding] = {}
    result: list[Finding] = []

    for f in sorted_findings:
        key = _dedup_key(f)
        if key not in canonical:
            canonical[key] = f
            result.append(f)
        else:
            f.duplicate_of = canonical[key].id
            result.append(f)

    return result


def infer_category_from_rule_id(rule_id: str) -> FindingCategory:
    """Heuristic: map rule ID keywords to FindingCategory."""
    r = rule_id.lower()
    if any(k in r for k in ("sql", "injection", "taint", "rce", "command")):
        return FindingCategory.INJECTION
    if any(k in r for k in ("eval", "exec")) and "subprocess" not in r:
        return FindingCategory.INJECTION
    if any(k in r for k in ("secret", "password", "credential", "api.key", "token", "hardcoded")):
        return FindingCategory.SECRETS
    if any(k in r for k in ("crypto", "weak", "md5", "sha1", "des", "random")):
        return FindingCategory.CRYPTOGRAPHY
    if any(k in r for k in ("auth", "session", "jwt", "csrf", "login")):
        return FindingCategory.AUTHENTICATION
    if any(k in r for k in ("path.traversal", "directory", "lfi", "rfi")):
        return FindingCategory.PATH_TRAVERSAL
    if "xss" in r or "cross.site" in r:
        return FindingCategory.XSS
    if "ssrf" in r:
        return FindingCategory.SSRF
    if any(k in r for k in ("deserializ", "pickle", "yaml.load", "marshal")):
        return FindingCategory.DESERIALIZATION
    if any(k in r for k in ("cve", "vuln")):
        return FindingCategory.DEPENDENCY_CVE
    if any(k in r for k in ("quality", "style", "complexity", "unused")):
        return FindingCategory.CODE_QUALITY
    return FindingCategory.OTHER
