"""Render pentest report HTML → PDF via WeasyPrint."""

import logging
from datetime import datetime, timezone
from jinja2 import Template

log = logging.getLogger("report_renderer")

REPORT_TEMPLATE = Template("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page { size: A4; margin: 2cm; }
  body { font-family: 'Helvetica Neue', Arial, sans-serif; color: #1a1a2e; font-size: 11pt; line-height: 1.5; }
  h1 { color: #e94560; border-bottom: 3px solid #e94560; padding-bottom: 8px; font-size: 22pt; }
  h2 { color: #16213e; border-bottom: 1px solid #ccc; padding-bottom: 4px; margin-top: 24px; }
  h3 { color: #0f3460; }
  .meta { color: #666; font-size: 9pt; margin-bottom: 20px; }
  .severity-critical { color: #fff; background: #dc2626; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
  .severity-high { color: #fff; background: #ea580c; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
  .severity-medium { color: #000; background: #facc15; padding: 2px 8px; border-radius: 4px; }
  .severity-low { color: #fff; background: #2563eb; padding: 2px 8px; border-radius: 4px; }
  .severity-info { color: #fff; background: #6b7280; padding: 2px 8px; border-radius: 4px; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 9pt; }
  th { background: #16213e; color: #fff; padding: 8px; text-align: left; }
  td { padding: 6px 8px; border-bottom: 1px solid #e5e7eb; }
  tr:nth-child(even) { background: #f8f9fa; }
  .stats-grid { display: flex; gap: 16px; margin: 16px 0; }
  .stat-card { background: #f1f5f9; border-radius: 8px; padding: 16px; flex: 1; text-align: center; }
  .stat-value { font-size: 24pt; font-weight: bold; color: #16213e; }
  .stat-label { font-size: 9pt; color: #666; }
  .finding-card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; margin: 8px 0; page-break-inside: avoid; }
  .evidence { background: #1a1a2e; color: #a3e635; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 8pt; white-space: pre-wrap; overflow-wrap: break-word; }
  .footer { text-align: center; color: #999; font-size: 8pt; margin-top: 40px; border-top: 1px solid #ccc; padding-top: 8px; }
</style>
</head>
<body>

<h1>{{ title }}</h1>
<div class="meta">Generated: {{ timestamp }} | Scope: {{ scope }}</div>

{% if summary %}
<h2>Executive Summary</h2>
<p>{{ summary.get('executive_summary', summary.get('summary', 'No summary available.')) }}</p>
{% endif %}

<h2>Finding Statistics</h2>
<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-value">{{ findings|length }}</div>
    <div class="stat-label">Total Findings</div>
  </div>
  {% for sev, count in agg_severity.items() %}
  <div class="stat-card">
    <div class="stat-value">{{ count }}</div>
    <div class="stat-label"><span class="severity-{{ sev }}">{{ sev|upper }}</span></div>
  </div>
  {% endfor %}
</div>

{% if agg_source %}
<h3>Findings by Source</h3>
<table>
  <tr><th>Source</th><th>Count</th></tr>
  {% for src, count in agg_source.items() %}
  <tr><td>{{ src }}</td><td>{{ count }}</td></tr>
  {% endfor %}
</table>
{% endif %}

<h2>Findings Detail</h2>
{% for f in findings %}
<div class="finding-card">
  <h3>
    <span class="severity-{{ f.get('severity', 'info') }}">{{ f.get('severity', 'info')|upper }}</span>
    {{ f.get('title', f.get('name', 'Untitled')) }}
  </h3>
  <table>
    <tr><td><strong>IP</strong></td><td>{{ f.get('ip', 'N/A') }}</td>
        <td><strong>Port</strong></td><td>{{ f.get('port', 'N/A') }}</td></tr>
    <tr><td><strong>Source</strong></td><td>{{ f.get('source', 'N/A') }}</td>
        <td><strong>CVE</strong></td><td>{{ f.get('cve', 'N/A') }}</td></tr>
  </table>
  {% if f.get('evidence') or f.get('output') %}
  <div class="evidence">{{ (f.get('evidence') or f.get('output', ''))[:500] }}</div>
  {% endif %}
</div>
{% endfor %}

<div class="footer">
  Pentest Dashboard Report &mdash; Confidential &mdash; {{ timestamp }}
</div>

</body>
</html>
""")


def render_pdf(
    title: str,
    findings: list[dict],
    aggregations: dict,
    summary: dict | None = None,
) -> bytes:
    """Render findings to PDF bytes."""
    from weasyprint import HTML

    # Sort findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(
        findings,
        key=lambda f: severity_order.get(f.get("severity", "info"), 5),
    )

    scope = ", ".join(set(f.get("ip", "unknown") for f in findings[:20]))
    if len(set(f.get("ip") for f in findings)) > 20:
        scope += " ..."

    html = REPORT_TEMPLATE.render(
        title=title,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        scope=scope or "All targets",
        findings=findings_sorted,
        summary=summary or {},
        agg_severity=aggregations.get("by_severity", {}),
        agg_source=aggregations.get("by_source", {}),
    )

    return HTML(string=html).write_pdf()
