"""Self-contained HTML report renderer for pqready scan results."""

from __future__ import annotations

from datetime import UTC, datetime

from jinja2 import Environment, select_autoescape

from ..core.models import ScanResult, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#16a34a",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>pqready report — {{ target_summary }}</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 "Helvetica Neue", Arial, sans-serif;
    background: #f8fafc;
    color: #0f172a;
    line-height: 1.5;
  }
  .container { max-width: 1080px; margin: 0 auto; padding: 32px 24px 64px; }
  header {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #f8fafc;
    padding: 32px 24px;
  }
  header .inner { max-width: 1080px; margin: 0 auto; }
  .logo { font-size: 28px; font-weight: 700; letter-spacing: -0.02em; }
  .logo .accent { color: #38bdf8; }
  .subtitle { color: #cbd5e1; margin-top: 4px; font-size: 14px; }
  h2 {
    font-size: 18px;
    margin: 32px 0 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid #e2e8f0;
  }
  .score-row { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 16px; }
  .score-card {
    flex: 1 1 220px;
    background: #fff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 16px;
  }
  .score-card .label { font-size: 12px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
  .score-card .value { font-size: 32px; font-weight: 700; margin-top: 4px; }
  .gauge {
    position: relative;
    height: 10px;
    background: #e2e8f0;
    border-radius: 999px;
    overflow: hidden;
    margin-top: 12px;
  }
  .gauge .fill {
    position: absolute;
    inset: 0 auto 0 0;
    width: {{ overall_score }}%;
    background: linear-gradient(90deg, #16a34a 0%, #ca8a04 50%, #dc2626 100%);
  }
  .badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    color: #fff;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .badge-pqc-yes { background: #16a34a; }
  .badge-pqc-no { background: #dc2626; }
  table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04); }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; vertical-align: top; }
  th { background: #f1f5f9; font-weight: 600; color: #475569; }
  tr:last-child td { border-bottom: none; }
  .finding {
    background: #fff;
    border: 1px solid #e2e8f0;
    border-left-width: 4px;
    border-radius: 6px;
    padding: 16px;
    margin: 12px 0;
  }
  .finding h3 { margin: 0 0 6px; font-size: 15px; }
  .finding .meta { font-size: 12px; color: #64748b; margin-bottom: 8px; }
  .finding .body { font-size: 14px; }
  .finding .evidence {
    background: #f1f5f9;
    padding: 8px 10px;
    border-radius: 4px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    margin: 8px 0;
    word-break: break-all;
  }
  .finding .remediation { font-size: 13px; }
  .counts { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
  .count {
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    color: #fff;
  }
  footer { text-align: center; color: #64748b; font-size: 12px; margin-top: 48px; padding-top: 16px; border-top: 1px solid #e2e8f0; }
  footer a { color: #2563eb; text-decoration: none; }
  .target-block { margin-bottom: 32px; }
  .err { color: #b91c1c; font-style: italic; }
</style>
</head>
<body>
<header>
  <div class="inner">
    <div class="logo">pq<span class="accent">ready</span></div>
    <div class="subtitle">PQC readiness report · {{ generated_at }}</div>
  </div>
</header>

<div class="container">

  <h2>Executive summary</h2>
  <div class="score-row">
    <div class="score-card">
      <div class="label">Overall risk score</div>
      <div class="value">{{ overall_score }} / 100</div>
      <div class="gauge"><div class="fill"></div></div>
    </div>
    <div class="score-card">
      <div class="label">PQC ready</div>
      <div class="value">
        {% if overall_pqc_ready %}
          <span class="badge badge-pqc-yes">Yes</span>
        {% else %}
          <span class="badge badge-pqc-no">No</span>
        {% endif %}
      </div>
      <div class="subtitle" style="color:#64748b;margin-top:8px;">
        {{ targets_scanned }} target(s) scanned · {{ total_findings }} finding(s)
      </div>
    </div>
    <div class="score-card">
      <div class="label">Findings by severity</div>
      <div class="counts">
        {% for sev in severity_order %}
          {% if counts[sev.value] %}
            <span class="count" style="background: {{ colors[sev.value] }}">
              {{ sev.value | upper }}: {{ counts[sev.value] }}
            </span>
          {% endif %}
        {% endfor %}
      </div>
    </div>
  </div>

  <h2>Migration priority matrix</h2>
  {% if priority_rows %}
    <table>
      <thead>
        <tr>
          <th>ID</th><th>Severity</th><th>Location</th>
          <th>Remediation</th><th>NIST ref</th>
        </tr>
      </thead>
      <tbody>
        {% for row in priority_rows %}
          <tr>
            <td><code>{{ row.id }}</code></td>
            <td>
              <span class="badge" style="background: {{ colors[row.severity] }}">
                {{ row.severity | upper }}
              </span>
            </td>
            <td>{{ row.location }}</td>
            <td>{{ row.remediation }}</td>
            <td>{{ row.nist_ref }}</td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
  {% else %}
    <p>No actionable findings. Recheck periodically as standards evolve.</p>
  {% endif %}

  <h2>Finding details</h2>
  {% for tgt in target_blocks %}
    <div class="target-block">
      <h3 style="margin-bottom:4px;">{{ tgt.target }} <span style="font-size:12px;color:#64748b;">({{ tgt.scan_type }})</span></h3>
      {% if tgt.error %}
        <p class="err">Scan error: {{ tgt.error }}</p>
      {% elif not tgt.findings %}
        <p style="color:#64748b;font-size:13px;">No findings.</p>
      {% endif %}
      {% for f in tgt.findings %}
        <div class="finding" style="border-left-color: {{ colors[f.severity] }};">
          <h3>
            <span class="badge" style="background: {{ colors[f.severity] }}">
              {{ f.severity | upper }}
            </span>
            {{ f.id }} — {{ f.title }}
          </h3>
          <div class="meta">{{ f.location }} · {{ f.nist_ref }}</div>
          <div class="body">{{ f.description }}</div>
          <div class="evidence">{{ f.evidence }}</div>
          <div class="remediation"><strong>Remediation:</strong> {{ f.remediation }}</div>
        </div>
      {% endfor %}
    </div>
  {% endfor %}

  <footer>
    Generated by <strong>pqready</strong> ·
    <a href="https://pypi.org/project/pqready/">pypi.org/project/pqready</a>
  </footer>
</div>
</body>
</html>
"""


def render_html(results: list[ScanResult], output_path: str) -> None:
    """Render scan results to a single self-contained HTML file."""

    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = env.from_string(_TEMPLATE)

    counts = {sev.value: 0 for sev in _SEVERITY_ORDER}
    target_blocks = []
    priority_rows = []
    total_findings = 0

    for r in results:
        target_blocks.append(
            {
                "target": r.target,
                "scan_type": r.scan_type,
                "error": r.error,
                "findings": _sorted_findings(r),
            }
        )
        for f in r.findings:
            counts[f.severity.value] += 1
            total_findings += 1
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                priority_rows.append(
                    {
                        "id": f.id,
                        "severity": f.severity.value,
                        "location": f.location,
                        "remediation": f.remediation,
                        "nist_ref": f.nist_ref,
                    }
                )

    overall_score = min(sum(r.risk_score for r in results), 100) if results else 0
    overall_pqc_ready = all(r.pqc_ready for r in results) if results else True

    if results:
        names = [r.target for r in results]
        target_summary = names[0] if len(names) == 1 else f"{len(names)} targets"
    else:
        target_summary = "no targets"

    html = template.render(
        target_summary=target_summary,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        overall_score=overall_score,
        overall_pqc_ready=overall_pqc_ready,
        counts=counts,
        colors={k.value: v for k, v in _SEVERITY_COLORS.items()},
        severity_order=_SEVERITY_ORDER,
        priority_rows=_sorted_priority(priority_rows),
        target_blocks=target_blocks,
        targets_scanned=len(results),
        total_findings=total_findings,
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)


def _sorted_findings(result: ScanResult):
    order = {s.value: i for i, s in enumerate(_SEVERITY_ORDER)}
    return sorted(result.findings, key=lambda f: (order[f.severity.value], f.id))


def _sorted_priority(rows):
    order = {s.value: i for i, s in enumerate(_SEVERITY_ORDER)}
    return sorted(rows, key=lambda r: (order[r["severity"]], r["id"]))
