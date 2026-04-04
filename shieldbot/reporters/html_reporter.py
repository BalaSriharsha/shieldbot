"""Self-contained HTML report generator using Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, BaseLoader, select_autoescape

from shieldbot.models import SecurityReport, Severity

_SEVERITY_BADGE = {
    Severity.CRITICAL: ("critical-badge", "CRITICAL"),
    Severity.HIGH: ("high-badge", "HIGH"),
    Severity.MEDIUM: ("medium-badge", "MEDIUM"),
    Severity.LOW: ("low-badge", "LOW"),
    Severity.INFO: ("info-badge", "INFO"),
}

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shieldbot Security Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #0f1117; color: #e2e8f0; line-height: 1.6; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  h1 { font-size: 2rem; color: #60a5fa; margin-bottom: 0.5rem; }
  h2 { font-size: 1.25rem; color: #94a3b8; margin: 2rem 0 1rem; }
  .meta { color: #64748b; font-size: 0.875rem; margin-bottom: 2rem; }
  .risk-banner { padding: 1rem 1.5rem; border-radius: 8px; margin: 1.5rem 0;
                  font-size: 1.5rem; font-weight: bold; }
  .risk-critical { background: #450a0a; color: #f87171; border: 1px solid #dc2626; }
  .risk-high { background: #431407; color: #fb923c; border: 1px solid #ea580c; }
  .risk-medium { background: #422006; color: #fbbf24; border: 1px solid #d97706; }
  .risk-low { background: #042f2e; color: #34d399; border: 1px solid #059669; }
  .risk-clean { background: #052e16; color: #4ade80; border: 1px solid #16a34a; }
  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin: 1.5rem 0; }
  .sev-card { padding: 1rem; border-radius: 8px; text-align: center; }
  .sev-critical { background: #450a0a; border: 1px solid #dc2626; }
  .sev-high { background: #431407; border: 1px solid #ea580c; }
  .sev-medium { background: #422006; border: 1px solid #d97706; }
  .sev-low { background: #042f2e; border: 1px solid #059669; }
  .sev-info { background: #1e293b; border: 1px solid #475569; }
  .sev-card .count { font-size: 2rem; font-weight: bold; }
  .sev-card .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em; }
  .summary-table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  .summary-table th, .summary-table td { padding: 0.75rem 1rem; text-align: left;
    border-bottom: 1px solid #1e293b; }
  .summary-table th { background: #1e293b; color: #94a3b8; font-weight: 600; }
  .summary-table tr:hover { background: #1e293b44; }
  .executive { background: #1e293b; border-radius: 8px; padding: 1.5rem;
               border-left: 4px solid #60a5fa; margin: 1.5rem 0; }
  .findings { margin-top: 1.5rem; }
  .finding { background: #1e293b; border-radius: 8px; margin-bottom: 0.75rem;
             overflow: hidden; border: 1px solid #334155; }
  .finding-header { padding: 1rem 1.25rem; cursor: pointer; display: flex;
                    align-items: center; gap: 1rem; user-select: none; }
  .finding-header:hover { background: #334155; }
  .finding-body { padding: 1rem 1.25rem; border-top: 1px solid #334155;
                  display: none; font-size: 0.875rem; }
  .finding-body.open { display: block; }
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;
            font-weight: bold; text-transform: uppercase; }
  .critical-badge { background: #450a0a; color: #f87171; border: 1px solid #dc2626; }
  .high-badge { background: #431407; color: #fb923c; border: 1px solid #ea580c; }
  .medium-badge { background: #422006; color: #fbbf24; border: 1px solid #d97706; }
  .low-badge { background: #042f2e; color: #34d399; border: 1px solid #059669; }
  .info-badge { background: #1e293b; color: #94a3b8; border: 1px solid #475569; }
  .meta-row { display: flex; gap: 1.5rem; flex-wrap: wrap; margin: 0.5rem 0; color: #94a3b8; }
  .meta-row span { font-size: 0.8rem; }
  .meta-key { color: #475569; }
  pre { background: #0f1117; border: 1px solid #334155; border-radius: 4px;
        padding: 0.75rem; overflow-x: auto; font-size: 0.8rem; margin-top: 0.5rem; }
  .remediation { background: #052e1633; border-left: 3px solid #16a34a;
                  padding: 0.75rem 1rem; margin-top: 0.75rem; border-radius: 0 4px 4px 0; }
  .fp-note { color: #94a3b8; font-style: italic; font-size: 0.8rem; }
  footer { color: #475569; font-size: 0.75rem; margin-top: 3rem; padding-top: 1rem;
            border-top: 1px solid #1e293b; }
</style>
</head>
<body>
<div class="container">
  <h1>Shieldbot Security Report</h1>
  <div class="meta">
    Repo: {{ report.repo_path }} &nbsp;|&nbsp;
    Scanned: {{ report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') }} &nbsp;|&nbsp;
    Duration: {{ "%.1f"|format(report.scan_duration_seconds) }}s &nbsp;|&nbsp;
    Languages: {{ report.languages_detected | join(", ") or "—" }}
  </div>

  {% if report.claude_analysis %}
  {% set rl = report.claude_analysis.risk_label | lower %}
  <div class="risk-banner risk-{{ rl }}">
    Risk Score: {{ report.claude_analysis.risk_score }}/100 &mdash; {{ report.claude_analysis.risk_label }}
  </div>
  {% endif %}

  <div class="summary-grid">
    {% for sev in ["critical","high","medium","low","info"] %}
    <div class="sev-card sev-{{ sev }}">
      <div class="count">{{ report.findings_by_severity.get(sev, 0) }}</div>
      <div class="label">{{ sev }}</div>
    </div>
    {% endfor %}
  </div>

  <h2>Scanner Results</h2>
  <table class="summary-table">
    <thead><tr>
      <th>Scanner</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Status</th>
    </tr></thead>
    <tbody>
    {% for result in report.scan_results %}
    {% set counts = namespace(critical=0, high=0, medium=0, low=0) %}
    {% for f in result.findings %}{% if not f.duplicate_of %}
      {% if f.severity.value == "critical" %}{% set counts.critical = counts.critical + 1 %}
      {% elif f.severity.value == "high" %}{% set counts.high = counts.high + 1 %}
      {% elif f.severity.value == "medium" %}{% set counts.medium = counts.medium + 1 %}
      {% elif f.severity.value == "low" %}{% set counts.low = counts.low + 1 %}
      {% endif %}
    {% endif %}{% endfor %}
    <tr>
      <td>{{ result.scanner }}</td>
      <td>{{ counts.critical or "—" }}</td>
      <td>{{ counts.high or "—" }}</td>
      <td>{{ counts.medium or "—" }}</td>
      <td>{{ counts.low or "—" }}</td>
      <td>{% if result.success %}<span style="color:#4ade80">OK</span>{% else %}
        <span style="color:#f87171">{{ result.error_message[:60] if result.error_message else "Error" }}</span>
      {% endif %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  {% if report.claude_analysis and report.claude_analysis.executive_summary %}
  <h2>Executive Summary</h2>
  <div class="executive">{{ report.claude_analysis.executive_summary | replace("\n", "<br>") }}</div>
  {% endif %}

  <h2>Findings</h2>
  <div class="findings">
  {% for f in report.all_findings | sort(attribute="severity.value") %}{% if not f.duplicate_of %}
  {% set badge_class, badge_label = severity_badge[f.severity] %}
  {% set is_fp = report.claude_analysis and f.id in report.claude_analysis.false_positive_ids %}
  <div class="finding" id="finding-{{ f.id }}">
    <div class="finding-header" onclick="toggle('{{ f.id }}')">
      <span class="badge {{ badge_class }}">{{ badge_label }}</span>
      <span>{{ f.title }}</span>
      {% if is_fp %}<span class="fp-note">&nbsp;(likely false positive)</span>{% endif %}
    </div>
    <div class="finding-body" id="body-{{ f.id }}">
      <div class="meta-row">
        <span><span class="meta-key">Rule:</span> {{ f.rule_id }}</span>
        <span><span class="meta-key">Scanner:</span> {{ f.scanner }}</span>
        <span><span class="meta-key">File:</span> {{ f.file_path }}:{{ f.line_start }}</span>
        {% if f.cwe_id %}<span><span class="meta-key">CWE:</span> {{ f.cwe_id }}</span>{% endif %}
        {% if f.cve_id %}<span><span class="meta-key">CVE:</span> {{ f.cve_id }}</span>{% endif %}
        {% if f.owasp_category %}<span><span class="meta-key">OWASP:</span> {{ f.owasp_category }}</span>{% endif %}
      </div>
      {% if f.description %}<p style="margin:0.5rem 0;">{{ f.description }}</p>{% endif %}
      {% if f.code_snippet %}<pre>{{ f.code_snippet | e }}</pre>{% endif %}
      {% if f.remediation %}
      <div class="remediation"><strong>Remediation:</strong><br>{{ f.remediation | replace("\n", "<br>") }}</div>
      {% endif %}
    </div>
  </div>
  {% endif %}{% endfor %}
  </div>

  <footer>
    Generated by <strong>Shieldbot</strong> &mdash; AI-powered security code review &mdash;
    Report ID: {{ report.report_id }}
  </footer>
</div>
<script>
function toggle(id) {
  const el = document.getElementById('body-' + id);
  el.classList.toggle('open');
}
</script>
</body>
</html>"""


def write_html_report(report: SecurityReport, output_file: str) -> None:
    """Render the security report as a self-contained HTML file."""
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape(['html', 'xml']))
    env.globals["severity_badge"] = _SEVERITY_BADGE
    template = env.from_string(_HTML_TEMPLATE)
    html = template.render(report=report)
    Path(output_file).write_text(html, encoding="utf-8")
