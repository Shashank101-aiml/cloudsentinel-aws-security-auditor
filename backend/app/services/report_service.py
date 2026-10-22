import csv
import io
import json
from datetime import datetime, timezone
from typing import List
from app.models.scan import Scan
from app.models.finding import Finding
from app.engine.sanitizer import Sanitizer


class ReportService:
    """Generates sanitized, safe downloadable reports in JSON, CSV, and HTML formats."""

    @staticmethod
    def generate_json(scan: Scan, findings: List[Finding]) -> str:
        data = {
            "report_metadata": {
                "generator": "CloudSentinel — AWS Security & Compliance Auditor",
                "version": "1.0.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "disclaimer": (
                    "CloudSentinel is a security auditing tool. Findings represent heuristic configuration "
                    "checks and do not guarantee complete security or official compliance."
                ),
            },
            "scan": {
                "id": scan.id,
                "account_id": scan.account_id,
                "scan_mode": scan.scan_mode,
                "status": scan.status,
                "risk_score": scan.risk_score,
                "total_resources_inspected": scan.total_resources_inspected,
                "checks_passed": scan.checks_passed,
                "checks_failed": scan.checks_failed,
                "checks_skipped": scan.checks_skipped,
                "findings_count": scan.findings_count,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
                "info_count": scan.info_count,
                "regions": scan.regions,
                "services": scan.services,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            },
            "findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "status": f.status,
                    "confidence": f.confidence,
                    "service": f.service,
                    "resource_id": f.resource_id,
                    "resource_type": f.resource_type,
                    "region": f.region,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "references": f.references,
                    "first_seen": f.first_seen.isoformat() if f.first_seen else None,
                }
                for f in findings
            ],
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def generate_csv(scan: Scan, findings: List[Finding]) -> str:
        """Outputs CSV with sanitization against formula injection."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        # Header row
        writer.writerow([
            "Finding ID",
            "Rule ID",
            "Severity",
            "Title",
            "Service",
            "Resource ID",
            "Resource Type",
            "Region",
            "Status",
            "Confidence",
            "Remediation",
        ])

        for f in findings:
            writer.writerow([
                Sanitizer.sanitize_csv_cell(f.id),
                Sanitizer.sanitize_csv_cell(f.rule_id),
                Sanitizer.sanitize_csv_cell(f.severity),
                Sanitizer.sanitize_csv_cell(f.title),
                Sanitizer.sanitize_csv_cell(f.service),
                Sanitizer.sanitize_csv_cell(f.resource_id),
                Sanitizer.sanitize_csv_cell(f.resource_type),
                Sanitizer.sanitize_csv_cell(f.region or "global"),
                Sanitizer.sanitize_csv_cell(f.status),
                Sanitizer.sanitize_csv_cell(f.confidence),
                Sanitizer.sanitize_csv_cell(f.remediation),
            ])

        return output.getvalue()

    @staticmethod
    def generate_html(scan: Scan, findings: List[Finding]) -> str:
        """Generates a standalone, professional HTML audit report with clean styling."""
        esc = Sanitizer.escape_html

        findings_rows = []
        for f in findings:
            sev_badge = f"""<span class="badge badge-{esc(f.severity).lower()}">{esc(f.severity)}</span>"""
            evidence_json = esc(json.dumps(f.evidence, indent=2))
            findings_rows.append(f"""
            <tr>
                <td>{sev_badge}</td>
                <td><code>{esc(f.rule_id)}</code></td>
                <td>
                    <strong>{esc(f.title)}</strong><br>
                    <small>{esc(f.description)}</small>
                </td>
                <td><code>{esc(f.service)}</code></td>
                <td><code>{esc(f.resource_id)}</code></td>
                <td>{esc(f.region or "global")}</td>
                <td><pre class="evidence-box">{evidence_json}</pre></td>
                <td>{esc(f.remediation)}</td>
            </tr>
            """)

        rows_html = "".join(findings_rows) if findings_rows else "<tr><td colspan='8'>No findings identified.</td></tr>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudSentinel Audit Report - {esc(scan.id)}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: #0f172a;
            color: #f8fafc;
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid #334155;
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .title {{
            font-size: 2rem;
            font-weight: 700;
            color: #38bdf8;
            margin: 0 0 0.5rem 0;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .meta-card {{
            background: #1e293b;
            border: 1px solid #334155;
            padding: 1.25rem;
            border-radius: 8px;
        }}
        .meta-label {{
            font-size: 0.85rem;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .meta-value {{
            font-size: 1.5rem;
            font-weight: 700;
            margin-top: 0.25rem;
        }}
        .risk-score {{
            color: {'#ef4444' if scan.risk_score >= 60 else ('#f59e0b' if scan.risk_score >= 30 else '#10b981')};
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            overflow: hidden;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 12px 16px;
            border-bottom: 1px solid #334155;
            text-align: left;
            vertical-align: top;
        }}
        th {{
            background: #0b1329;
            color: #94a3b8;
            text-transform: uppercase;
            font-size: 0.75rem;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 0.75rem;
        }}
        .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-high {{ background: #7c2d12; color: #fdba74; }}
        .badge-medium {{ background: #713f12; color: #fde047; }}
        .badge-low {{ background: #14532d; color: #86efac; }}
        .badge-info {{ background: #1e3a8a; color: #93c5fd; }}
        .evidence-box {{
            max-width: 250px;
            max-height: 120px;
            overflow: auto;
            background: #090d16;
            padding: 6px;
            border-radius: 4px;
            font-size: 0.75rem;
            margin: 0;
            color: #cbd5e1;
        }}
        .footer {{
            margin-top: 3rem;
            padding-top: 1rem;
            border-top: 1px solid #334155;
            font-size: 0.8rem;
            color: #64748b;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">CloudSentinel — AWS Security & Compliance Report</h1>
            <div>Target Account: <strong>{esc(scan.account_id)}</strong> | Scan ID: <code>{esc(scan.id)}</code> | Mode: <strong>{esc(scan.scan_mode).upper()}</strong></div>
        </div>

        <div class="meta-grid">
            <div class="meta-card">
                <div class="meta-label">Overall Risk Score</div>
                <div class="meta-value risk-score">{scan.risk_score} / 100</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Total Findings</div>
                <div class="meta-value">{scan.findings_count}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Critical / High</div>
                <div class="meta-value" style="color: #ef4444;">{scan.critical_count} / {scan.high_count}</div>
            </div>
            <div class="meta-card">
                <div class="meta-label">Resources Inspected</div>
                <div class="meta-value">{scan.total_resources_inspected}</div>
            </div>
        </div>

        <h2>Security Findings Detail</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Rule</th>
                    <th>Title & Description</th>
                    <th>Service</th>
                    <th>Resource</th>
                    <th>Region</th>
                    <th>Evidence</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>

        <div class="footer">
            <p><strong>Disclaimer:</strong> CloudSentinel is a read-only configuration audit framework. Findings represent automated rule evaluation and do not replace professional compliance validation.</p>
        </div>
    </div>
</body>
</html>"""
        return html_content
