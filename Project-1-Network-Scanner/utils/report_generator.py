"""
Report Generator Module
=======================
Generates scan reports in HTML and JSON formats.

In a corporate environment, reporting is critical:
- Security teams need clear, actionable reports
- Management needs executive summaries with risk levels
- Compliance requires documented evidence of security assessments
- ISO 27001 (used at Tüpraş) requires regular security reviews
"""

import json
import os
from datetime import datetime


class ReportGenerator:
    """Generates professional security scan reports."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_json_report(self, scan_data: dict, filename: str = None) -> str:
        """Generate a JSON report for machine consumption / API integration."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.json"

        filepath = os.path.join(self.output_dir, filename)
        
        report = {
            "report_metadata": {
                "tool": "Network Scanner v1.0",
                "generated_at": datetime.now().isoformat(),
                "report_type": "Network Scan Report",
            },
            "scan_results": scan_data,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"[*] JSON report saved: {filepath}")
        return filepath

    def generate_html_report(self, scan_data: dict, filename: str = None) -> str:
        """Generate a professional HTML report for human review."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{timestamp}.html"

        filepath = os.path.join(self.output_dir, filename)

        target = scan_data.get("target", "Unknown")
        scan_time = scan_data.get("scan_time", "")
        duration = scan_data.get("duration_seconds", 0)
        open_ports = scan_data.get("open_ports", [])
        services = scan_data.get("services", [])
        hosts = scan_data.get("discovered_hosts", [])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #0a0e17;
            color: #e0e0e0;
            padding: 2rem;
        }}
        .report-header {{
            background: linear-gradient(135deg, #1a1f36, #2d1b69);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid rgba(99, 102, 241, 0.3);
        }}
        .report-header h1 {{
            font-size: 1.8rem;
            background: linear-gradient(135deg, #818cf8, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .meta {{ color: #9ca3af; font-size: 0.9rem; }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: rgba(30, 41, 59, 0.8);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid rgba(99, 102, 241, 0.2);
        }}
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
            background: linear-gradient(135deg, #818cf8, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .stat-label {{ color: #9ca3af; margin-top: 0.5rem; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
        }}
        th {{
            background: rgba(99, 102, 241, 0.2);
            padding: 0.8rem 1rem;
            text-align: left;
            font-weight: 600;
            color: #818cf8;
        }}
        td {{
            padding: 0.7rem 1rem;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        tr:hover td {{ background: rgba(99, 102, 241, 0.05); }}
        .badge {{
            padding: 0.2rem 0.6rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        .badge-open {{ background: rgba(34, 197, 94, 0.2); color: #4ade80; }}
        .badge-warning {{ background: rgba(251, 191, 36, 0.2); color: #fbbf24; }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; }}
        .badge-ot {{ background: rgba(168, 85, 247, 0.2); color: #a855f7; }}
        .section {{
            background: rgba(30, 41, 59, 0.5);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid rgba(99, 102, 241, 0.15);
        }}
        .section h2 {{
            color: #818cf8;
            margin-bottom: 1rem;
            font-size: 1.3rem;
        }}
        .warning-box {{
            background: rgba(251, 191, 36, 0.1);
            border: 1px solid rgba(251, 191, 36, 0.3);
            border-radius: 8px;
            padding: 1rem;
            margin: 0.5rem 0;
        }}
        .danger-box {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 1rem;
            margin: 0.5rem 0;
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <h1>🛡️ Network Scan Report</h1>
        <p class="meta">Target: {target} | Scan Time: {scan_time} | Duration: {duration}s</p>
        <p class="meta">Generated by: Security-Fundamentals Network Scanner v1.0</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">{scan_data.get('open_count', len(open_ports))}</div>
            <div class="stat-label">Open Ports</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{scan_data.get('closed_count', 0)}</div>
            <div class="stat-label">Closed Ports</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{scan_data.get('filtered_count', 0)}</div>
            <div class="stat-label">Filtered Ports</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{scan_data.get('ports_scanned', 0)}</div>
            <div class="stat-label">Total Scanned</div>
        </div>
    </div>
"""

        # Open Ports Table
        if open_ports:
            html += """
    <div class="section">
        <h2>📡 Open Ports</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Description</th>
                    <th>RTT</th>
                    <th>Flags</th>
                </tr>
            </thead>
            <tbody>
"""
            for port in open_ports:
                flags = ""
                if port.get("is_ot_port"):
                    flags += '<span class="badge badge-ot">OT/ICS</span> '
                html += f"""
                <tr>
                    <td><strong>{port['port']}</strong></td>
                    <td><span class="badge badge-open">OPEN</span></td>
                    <td>{port.get('service', 'Unknown')}</td>
                    <td>{port.get('description', '')}</td>
                    <td>{port.get('rtt_ms', '')}ms</td>
                    <td>{flags}</td>
                </tr>
"""
            html += """
            </tbody>
        </table>
    </div>
"""

        # Services section
        if services:
            html += """
    <div class="section">
        <h2>🔍 Service Details & Banners</h2>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Banner</th>
                    <th>SSL</th>
                </tr>
            </thead>
            <tbody>
"""
            for svc in services:
                ssl_badge = '<span class="badge badge-open">Yes</span>' if svc.get("ssl") else "No"
                banner_short = (svc.get("banner", "")[:80] + "...") if len(svc.get("banner", "")) > 80 else svc.get("banner", "")
                html += f"""
                <tr>
                    <td>{svc['port']}</td>
                    <td>{svc.get('service', '')}</td>
                    <td>{svc.get('version', '')}</td>
                    <td><code>{banner_short}</code></td>
                    <td>{ssl_badge}</td>
                </tr>
"""
            html += """
            </tbody>
        </table>
    </div>
"""

        # Security Warnings
        html += self._generate_security_section(open_ports, services)

        html += """
    <div class="section" style="text-align: center; color: #6b7280; font-size: 0.85rem;">
        <p>Report generated by Security-Fundamentals Network Scanner</p>
        <p>This tool is for authorized security testing only.</p>
    </div>
</body>
</html>
"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[*] HTML report saved: {filepath}")
        return filepath

    def _generate_security_section(self, open_ports, services) -> str:
        """Generate security warnings section of the report."""
        warnings = []
        
        risky_services = {
            23: ("CRITICAL", "Telnet detected - transmits all data including passwords in cleartext"),
            21: ("HIGH", "FTP detected - credentials sent in cleartext, consider SFTP"),
            445: ("HIGH", "SMB detected - frequent ransomware target (WannaCry, NotPetya used SMB)"),
            3389: ("HIGH", "RDP detected - common brute force target, ensure NLA is enabled"),
            502: ("CRITICAL", "Modbus detected - NO built-in authentication or encryption (OT risk!)"),
            161: ("HIGH", "SNMP detected - can leak device configurations, use SNMPv3"),
            139: ("MEDIUM", "NetBIOS detected - can leak system information"),
            1433: ("MEDIUM", "MSSQL detected - ensure not externally accessible"),
            3306: ("MEDIUM", "MySQL detected - ensure strong authentication is configured"),
        }

        for port in open_ports:
            p = port["port"]
            if p in risky_services:
                severity, msg = risky_services[p]
                warnings.append((severity, p, msg))

        for svc in (services or []):
            for note in svc.get("security_notes", []):
                severity = "HIGH" if "CRITICAL" in note else "MEDIUM"
                warnings.append((severity, svc["port"], note))

        if not warnings:
            return ""

        html = """
    <div class="section">
        <h2>⚠️ Security Findings</h2>
"""
        for severity, port, msg in warnings:
            box_class = "danger-box" if severity in ("CRITICAL", "HIGH") else "warning-box"
            html += f"""
        <div class="{box_class}">
            <strong>[{severity}] Port {port}:</strong> {msg}
        </div>
"""
        html += "    </div>\n"
        return html
