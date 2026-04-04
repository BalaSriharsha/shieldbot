"""JSON report output for shieldbot."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from shieldbot.models import SecurityReport


def write_json_report(report: SecurityReport, output_file: str | None = None) -> str:
    """Serialize report to JSON. Writes to file or returns as string."""
    data = report.model_dump(mode="json")

    # Add a flat summary block for easy parsing in CI
    data["summary"] = {
        "total": report.total_findings,
        "critical": report.findings_by_severity.get("critical", 0),
        "high": report.findings_by_severity.get("high", 0),
        "medium": report.findings_by_severity.get("medium", 0),
        "low": report.findings_by_severity.get("low", 0),
        "info": report.findings_by_severity.get("info", 0),
    }

    text = json.dumps(data, indent=2, default=str)

    if output_file:
        Path(output_file).write_text(text, encoding="utf-8")
    return text
