"""HTML report generation for ReconForge."""

import json
from html import escape
from datetime import datetime, timezone
from pathlib import Path
from typing import Union, Dict, Any

from jinja2 import Environment, PackageLoader, select_autoescape

from reconforge.core.logging import get_logger
from reconforge.core.models import ScanReport, PortScanResult

logger = get_logger(__name__)


def _format_port_entry(port: Any) -> dict:
    """Normalize a port entry from historical or future result shapes."""
    if isinstance(port, int):
        return {"port": port, "service": None, "banner": None}
    if not isinstance(port, dict):
        return {"port": str(port), "service": None, "banner": None}

    banner = port.get("banner")
    if isinstance(banner, dict):
        banner = banner.get("banner") or banner.get("raw") or banner.get("text")

    return {
        "port": port.get("port") or port.get("number") or port.get("id") or "-",
        "service": port.get("service") or port.get("name"),
        "banner": banner,
    }


def normalize_scan_result(result: dict) -> dict:
    """Normalize a cumulative scan result for simple HTML rendering."""
    data = result.get("data", {})
    raw_hosts = data.get("hosts") or data.get("live_hosts") or data.get("discovered_hosts") or []
    normalized_hosts = []

    for host in raw_hosts:
        if not isinstance(host, dict):
            normalized_hosts.append(
                {
                    "host": str(host),
                    "status": "-",
                    "open_ports": None,
                }
            )
            continue

        host_name = (
            host.get("ip_address")
            or host.get("ip")
            or host.get("host")
            or host.get("hostname")
            or "-"
        )
        status = host.get("status")
        if not status:
            if host.get("alive") is True:
                status = "up"
            elif host.get("alive") is False:
                status = "down"
            else:
                status = "-"

        if "open_ports" in host:
            raw_ports = host.get("open_ports") or []
        elif "ports" in host:
            raw_ports = host.get("ports") or []
        elif "services" in host:
            raw_ports = host.get("services") or []
        elif "open_ports" in data:
            raw_ports = data.get("open_ports") or []
        else:
            raw_ports = None

        normalized_hosts.append(
            {
                "host": host_name,
                "status": str(status),
                "open_ports": (
                    [_format_port_entry(port) for port in raw_ports]
                    if raw_ports is not None
                    else None
                ),
            }
        )

    return {
        "target": result.get("target") or data.get("target") or "-",
        "timestamp": result.get("timestamp") or data.get("timestamp") or "-",
        "hosts": normalized_hosts,
    }


class HTMLReporter:
    """Generate HTML reports."""
    
    def __init__(self):
        """Initialize HTML reporter with Jinja2 environment."""
        self.env = Environment(
            loader=PackageLoader("reconforge", "reporting/templates"),
            autoescape=select_autoescape(["html", "xml", "j2"]),
        )
    
    def _prepare_scan_data(self, scan_report: ScanReport) -> Dict[str, Any]:
        """Prepare scan report data for template rendering.
        
        Args:
            scan_report: ScanReport object
            
        Returns:
            Dictionary with formatted data for template
        """
        # Collect port details
        port_details = []
        for host in scan_report.hosts:
            if host.open_ports:
                port_details.append({
                    "host": host.ip_address,
                    "ports": [
                        {
                            "port": p.port,
                            "service": p.service,
                            "open": p.open,
                            "banner": p.banner.banner if p.banner else None,
                        }
                        for p in host.open_ports
                    ]
                })
        
        # Prepare hosts data
        hosts_data = []
        for host in scan_report.hosts:
            services = [p.service for p in host.open_ports if p.service]
            hosts_data.append({
                "ip": host.ip_address,
                "hostname": host.hostname,
                "alive": host.alive,
                "open_ports": [{"port": p.port} for p in host.open_ports if p.open],
                "services": services,
            })
        
        return {
            "scan_id": scan_report.scan_id,
            "target": scan_report.target,
            "start_time": scan_report.start_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "end_time": scan_report.end_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "duration_seconds": scan_report.duration,
            "alive_hosts": scan_report.alive_hosts_count,
            "total_open_ports": scan_report.total_open_ports,
            "hosts_count": len(scan_report.hosts),
            "timeout": scan_report.scan_config.timeout,
            "workers": scan_report.scan_config.workers,
            "ports": scan_report.scan_config.ports,
            "hosts": hosts_data,
            "port_details": port_details,
        }
    
    def report_scan(
        self,
        scan_report: ScanReport,
        output_file: Union[str, Path]
    ) -> Path:
        """Generate HTML scan report.
        
        Args:
            scan_report: ScanReport object
            output_file: Path to output HTML file
            
        Returns:
            Path to generated report
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Prepare data
        template_data = self._prepare_scan_data(scan_report)
        
        # Render template
        template = self.env.get_template("report.html.j2")
        html_content = template.render(report=template_data)
        
        # Write file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to {output_path}")
        return output_path

    @staticmethod
    def _format_value(value: Any) -> str:
        if value is None:
            return "-"
        if isinstance(value, (list, tuple)):
            return ", ".join(str(item) for item in value) if value else "-"
        if isinstance(value, dict):
            return ", ".join(f"{key}: {val}" for key, val in value.items()) if value else "-"
        return str(value)

    @staticmethod
    def _render_table(headers: list, rows: list) -> str:
        if not rows:
            return '<p class="muted">No data collected.</p>'

        head = "".join(f"<th>{escape(str(header))}</th>" for header in headers)
        body_rows = []
        for row in rows:
            cells = "".join(
                f"<td>{escape(HTMLReporter._format_value(cell))}</td>"
                for cell in row
            )
            body_rows.append(f"<tr>{cells}</tr>")
        return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"

    @staticmethod
    def _format_normalized_port(port: dict) -> str:
        value = str(port.get("port", "-"))
        service = port.get("service")
        banner = port.get("banner")
        if service:
            value = f"{value}/{service}"
        if banner:
            value = f"{value} ({str(banner)[:120]})"
        return value

    @staticmethod
    def _host_ports_text(host: dict) -> str:
        ports = host.get("open_ports")
        if ports is None:
            return "No open ports recorded"
        if not ports:
            return "No open ports found"

        return ", ".join(HTMLReporter._format_normalized_port(port) for port in ports)

    @staticmethod
    def _scan_rows(item: dict) -> list:
        scan = normalize_scan_result(item)
        hosts = scan["hosts"]

        if not hosts:
            return [[
                scan["timestamp"],
                scan["target"],
                "-",
                "No discovered/live hosts recorded",
                "No open ports recorded",
            ]]

        rows = []
        for host in hosts:
            rows.append([
                scan["timestamp"],
                scan["target"],
                host["host"],
                host["status"],
                HTMLReporter._host_ports_text(host),
            ])
        return rows

    @staticmethod
    def _result_sections(store: dict, summary_only: bool) -> str:
        if summary_only:
            return ""

        results = store.get("results", [])
        sections = []
        section_titles = {
            "scan": "Scan Results",
            "ports": "Port Scan Results",
            "banner": "Banner Results",
            "http": "HTTP/TLS Results",
        }

        for result_type, title in section_titles.items():
            typed_results = [item for item in results if item.get("type") == result_type]
            rows = []
            headers_by_type = {
                "scan": ["Timestamp", "Target", "Host", "Status", "Open Ports"],
                "ports": ["Timestamp", "Target", "Ports Scanned", "Open Ports"],
                "banner": ["Timestamp", "Target", "Banners"],
                "http": [
                    "Timestamp",
                    "Target",
                    "Status",
                    "Server",
                    "Redirects",
                    "TLS Subject",
                    "TLS Not After",
                ],
            }
            headers = headers_by_type[result_type]

            for item in typed_results:
                data = item.get("data", {})
                if result_type == "scan":
                    rows.extend(HTMLReporter._scan_rows(item))
                elif result_type == "ports":
                    rows.append([
                        item.get("timestamp"),
                        item.get("target"),
                        len(data.get("scanned_ports", [])),
                        [port.get("port") for port in data.get("open_ports", [])],
                    ])
                elif result_type == "banner":
                    rows.append([
                        item.get("timestamp"),
                        item.get("target"),
                        [
                            f"{port.get('port')}: {port.get('banner', '-')[:80]}"
                            for port in data.get("ports", [])
                        ],
                    ])
                else:
                    cert = data.get("tls_certificate") or {}
                    rows.append([
                        item.get("timestamp"),
                        item.get("target"),
                        data.get("status_code"),
                        data.get("server_header"),
                        data.get("redirects", []),
                        cert.get("subject"),
                        cert.get("not_after"),
                    ])

            sections.append(f"<section><h2>{title}</h2>{HTMLReporter._render_table(headers, rows)}</section>")

        return "\n".join(sections)

    @staticmethod
    def report_results_store(
        store: dict,
        output_file: Union[str, Path],
        summary_only: bool = False,
    ) -> Path:
        """Generate an HTML report from a cumulative results store."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        summary = store.get("summary", {})
        counts_rows = [
            [result_type, count]
            for result_type, count in sorted(summary.get("result_counts", {}).items())
        ]
        targets_rows = [
            [item.get("target"), item.get("result_count")]
            for item in summary.get("targets_summary", [])
        ]
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconForge Cumulative Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; background: #f5f7fa; color: #1f2933; }}
        header {{ background: #172033; color: #fff; padding: 28px 40px; }}
        main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
        section {{ background: #fff; border: 1px solid #d9e2ec; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        h1, h2 {{ margin-top: 0; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; }}
        .metric {{ background: #eef2f7; border-radius: 6px; padding: 16px; }}
        .metric strong {{ display: block; font-size: 1.8rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ border-bottom: 1px solid #d9e2ec; padding: 10px; text-align: left; vertical-align: top; }}
        th {{ background: #eef2f7; }}
        .muted {{ color: #637083; }}
        footer {{ padding: 20px 40px; color: #637083; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <header>
        <h1>ReconForge Cumulative Report</h1>
        <p>Authorized reconnaissance summary generated at {escape(generated_at)}</p>
    </header>
    <main>
        <section>
            <h2>Session Summary</h2>
            <div class="grid">
                <div class="metric"><span>Session ID</span><strong>{escape(str(store.get("session_id", "-")))}</strong></div>
                <div class="metric"><span>Total Results</span><strong>{escape(str(summary.get("total_results", 0)))}</strong></div>
                <div class="metric"><span>Unique Targets</span><strong>{escape(str(summary.get("unique_targets", 0)))}</strong></div>
            </div>
            <p><strong>Created:</strong> {escape(str(store.get("created_at", "-")))}</p>
            <p><strong>Updated:</strong> {escape(str(store.get("updated_at", "-")))}</p>
        </section>
        <section>
            <h2>Result Counts</h2>
            {HTMLReporter._render_table(["Type", "Count"], counts_rows)}
        </section>
        <section>
            <h2>Targets Summary</h2>
            {HTMLReporter._render_table(["Target", "Results"], targets_rows)}
        </section>
        {HTMLReporter._result_sections(store, summary_only)}
    </main>
    <footer>
        Use ReconForge only on systems and networks where you have explicit authorization.
        This report is for defensive security testing and authorized reconnaissance only.
    </footer>
</body>
</html>
"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"Cumulative HTML report saved to {output_path}")
        return output_path
    
    @staticmethod
    def report_from_json(
        json_file: Union[str, Path],
        output_file: Union[str, Path]
    ) -> Path:
        """Generate HTML report from JSON file.
        
        Args:
            json_file: Path to JSON report file
            output_file: Path to output HTML file
            
        Returns:
            Path to generated report
        """
        # Read JSON file
        with open(json_file, "r") as f:
            data = json.load(f)
        
        # Convert timestamps
        for host in data.get("hosts", []):
            if "timestamp" in host:
                host["timestamp"] = datetime.fromisoformat(
                    host["timestamp"].replace("Z", "+00:00")
                )
        
        # Create ScanReport from data
        scan_report = ScanReport(**data)
        
        # Generate report
        reporter = HTMLReporter()
        return reporter.report_scan(scan_report, output_file)
