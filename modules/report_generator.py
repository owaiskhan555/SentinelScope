"""Standalone Executive HTML Security & Forensics Audit Report Generator."""

from __future__ import annotations

import html
from datetime import datetime, timezone


def build_html_audit_report(
    integrity_summary: dict | None,
    email_reports: list[dict],
) -> str:
    """Render a standalone HTML security audit report downloadable from Streamlit."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    fim_section = "<p>No batch file integrity verification executed in this session.</p>"
    if integrity_summary:
        rows_html = ""
        for rec in integrity_summary.get("records", []):
            status = html.escape(str(rec["Status"]))
            color = "#10B981" if "VERIFIED" in status else "#EF4444"
            rows_html += f"""
            <tr>
                <td>{html.escape(str(rec['File Name']))}</td>
                <td style="color:{color};font-weight:bold;">{status}</td>
                <td>{rec['Size (Bytes)']}</td>
                <td>{rec['Avalanche Flip %']}%</td>
                <td style="font-family:monospace;font-size:11px;">{html.escape(str(rec['Actual SHA-256']))}</td>
            </tr>
            """
        fim_section = f"""
        <p><strong>Integrity Score:</strong> {integrity_summary['integrity_score']}%
           ({integrity_summary['verified_count']} Verified / {integrity_summary['tampered_count']} Tampered)</p>
        <table>
            <thead>
                <tr>
                    <th>File Name</th>
                    <th>Status</th>
                    <th>Size</th>
                    <th>Avalanche Bit Flip</th>
                    <th>SHA-256 Digest</th>
                </tr>
            </thead>
            <tbody>{rows_html}</tbody>
        </table>
        """

    email_section = "<p>No email forensic investigations executed in this session.</p>"
    if email_reports:
        em_rows = ""
        for rep in email_reports:
            hdr = rep["headers"]
            auth = rep["auth"]
            verdict = html.escape(rep["verdict"])
            v_color = "#EF4444" if "HIGH RISK" in verdict else ("#F59E0B" if "SUSPICIOUS" in verdict else "#10B981")
            em_rows += f"""
            <tr>
                <td>{html.escape(rep['source_filename'])}</td>
                <td>{html.escape(hdr['from_address'])}</td>
                <td>{html.escape(hdr['subject'])}</td>
                <td>SPF: {auth['spf']} | DKIM: {auth['dkim']} | DMARC: {auth['dmarc']}</td>
                <td style="color:{v_color};font-weight:bold;">{rep['risk_score']}/100 — {verdict}</td>
            </tr>
            """
        email_section = f"""
        <table>
            <thead>
                <tr>
                    <th>Artifact</th>
                    <th>Sender</th>
                    <th>Subject</th>
                    <th>Authentication</th>
                    <th>Risk Verdict</th>
                </tr>
            </thead>
            <tbody>{em_rows}</tbody>
        </table>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SentinelScope — Security & Forensics Audit Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0B1120; color: #E2E8F0; padding: 32px; }}
  .card {{ background: #111827; border: 1px solid #1F2937; border-radius: 10px; padding: 22px; margin-bottom: 24px; }}
  h1 {{ color: #00E5FF; margin-bottom: 4px; }}
  h2 {{ color: #38BDF8; border-bottom: 1px solid #1E293B; padding-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  th, td {{ border: 1px solid #1E293B; padding: 10px; text-align: left; font-size: 13px; }}
  th {{ background: #1E293B; color: #00E5FF; }}
</style>
</head>
<body>
  <div class="card">
    <h1>SentinelScope — Security & Digital Forensics Audit Report</h1>
    <p>Generated: <strong>{generated_at}</strong> | Modules: Cryptographic File Integrity (SHA-256) & RFC-5322 Email Forensics</p>
  </div>
  <div class="card">
    <h2>1. Cryptographic File Integrity Audit</h2>
    {fim_section}
  </div>
  <div class="card">
    <h2>2. Email Threat & Header Forensics Audit</h2>
    {email_section}
  </div>
</body>
</html>
"""
