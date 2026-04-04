"""Configuration constants for shieldbot."""

from __future__ import annotations

# Claude model to use
CLAUDE_MODEL = "claude-sonnet-4-6"

# Semgrep rulesets always applied regardless of detected language
SEMGREP_ALWAYS_RULESETS = [
    "p/owasp-top-ten",
    "p/secrets",
    "p/cwe-top-25",
    "p/sql-injection",
    "p/command-injection",
    "p/ssrf",
]

# Additional rulesets keyed by detected language
SEMGREP_LANGUAGE_RULESETS: dict[str, list[str]] = {
    "python": ["p/security-audit", "p/python", "p/django", "p/flask", "p/bandit"],
    "javascript": ["p/security-audit", "p/javascript", "p/react", "p/express", "p/xss"],
    "typescript": ["p/security-audit", "p/typescript", "p/react"],
    "java": ["p/security-audit", "p/java"],
    "go": ["p/security-audit", "p/go"],
    "ruby": ["p/security-audit", "p/ruby", "p/rails"],
    "php": ["p/security-audit", "p/php"],
    "kotlin": ["p/security-audit"],
    "scala": ["p/security-audit"],
    "c": ["p/security-audit"],
    "cpp": ["p/security-audit"],
    "csharp": ["p/security-audit"],
    "rust": ["p/security-audit"],
}

# Scanner priority for deduplication (lower = higher priority, keeps its data)
SCANNER_PRIORITY: dict[str, int] = {
    "semgrep": 0,
    "bandit": 1,
    "ruff": 2,
    "detect-secrets": 3,
    "gitleaks": 3,
    "pip-audit": 4,
    "npm-audit": 4,
}

# Semgrep subprocess settings
SEMGREP_TIMEOUT_PER_FILE = 300   # seconds
SEMGREP_MAX_MEMORY_MB = 2000
SEMGREP_JOBS = 4
SEMGREP_OVERALL_TIMEOUT = 600    # 10 minutes total

# Scanners that are optional (warn but don't fail if missing)
OPTIONAL_SCANNERS = {"ruff", "gitleaks"}

# Max lines of code snippet to store per finding
MAX_SNIPPET_LINES = 10

# Severity thresholds for exit codes
EXIT_CODE_MEDIUM = 1
EXIT_CODE_HIGH = 2
EXIT_CODE_CRITICAL = 3
