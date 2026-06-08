"""HTML report generation for ReconForge."""

import json
from datetime import datetime
from pathlib import Path
from typing import Union, List, Dict, Any, Optional

from jinja2 import Environment, PackageLoader, select_autoescape

from reconforge.core.logging import get_logger
from reconforge.core.models import ScanReport, PortScanResult

logger = get_logger(__name__)


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
