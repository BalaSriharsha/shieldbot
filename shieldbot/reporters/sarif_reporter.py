"""SARIF 2.1.0 output for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from pathlib import Path

from shieldbot.models import Finding, SecurityReport, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def write_sarif_report(report: SecurityReport, output_file: str) -> None:
    """Write a SARIF 2.1.0 file suitable for GitHub Advanced Security upload."""
    # Group findings by scanner for separate runs
    by_scanner: dict[str, list[Finding]] = {}
    for f in report.all_findings:
        if f.duplicate_of:
            continue
        by_scanner.setdefault(f.scanner, []).append(f)

    runs = []
    for scanner_name, findings in by_scanner.items():
        rules: dict[str, dict] = {}
        results = []

        for f in findings:
            # Build rule entry
            if f.rule_id not in rules:
                help_text = f.description or f.title
                if f.cwe_id:
                    help_text += f"\n\nCWE: {f.cwe_id}"
                if f.owasp_category:
                    help_text += f"\nOWASP: {f.owasp_category}"
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title[:100],
                    "shortDescription": {"text": f.title[:100]},
                    "fullDescription": {"text": help_text},
                    "helpUri": f.references[0] if f.references else "",
                    "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                    "properties": {
                        "tags": [f.category.value],
                        "precision": f.confidence,
                        "severity": f.severity.value,
                    },
                }

            result: dict = {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.description or f.title},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(f.line_start, 1),
                                **({"endLine": f.line_end} if f.line_end else {}),
                                **({"startColumn": f.column} if f.column else {}),
                            },
                        }
                    }
                ],
            }

            if f.code_snippet:
                result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": f.code_snippet[:500]
                }

            results.append(result)

        runs.append({
            "tool": {
                "driver": {
                    "name": f"shieldbot/{scanner_name}",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/shieldbot",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }

    Path(output_file).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
