# shieldbot-mcp

AI-powered security code review MCP server for Claude Code.

Combines **Semgrep (5,000+ rules)**, bandit, ruff, detect-secrets, pip-audit, and npm-audit with Claude's security expertise to deliver prioritized, actionable security reports.

## Install

```bash
pip install shieldbot-mcp
```

Or run directly via `uvx` (recommended for MCP):
```bash
uvx shieldbot-mcp
```

## Usage with Claude Code

Install the plugin:
```
/plugin install shieldbot
```

Then ask Claude naturally:
- *"scan this repo for security issues"*
- *"check for hardcoded secrets"*
- *"audit my dependencies for CVEs"*

Or use the slash command:
```
/shieldbot-scan .
/shieldbot-scan /path/to/repo --min-severity high
/shieldbot-scan . --git-history
```

## MCP tools exposed

| Tool | Description |
|------|-------------|
| `scan_repository` | Full parallel security scan → JSON report |
| `check_scanner_tools` | Check which scanners are installed |

## Add to any MCP client

```json
{
  "mcpServers": {
    "shieldbot": {
      "command": "uvx",
      "args": ["shieldbot-mcp"]
    }
  }
}
```

## Scanners

| Scanner | Coverage |
|---------|---------|
| Semgrep 5,000+ rules | OWASP Top 10, CWE Top 25, injection, XSS, SSRF, taint |
| bandit | Python security |
| ruff | Python quality + security |
| detect-secrets | API keys, passwords, tokens |
| pip-audit | Python CVEs (PyPI Advisory DB) |
| npm audit | Node.js CVEs |

## Publish to PyPI

```bash
pip install hatchling build twine
python -m build
twine upload dist/*
```

## License

MIT
