"""JSON report generation for ReconForge."""

import json
from datetime import datetime
from pathlib import Path
from typing import Union

from reconforge.core.logging import get_logger
from reconforge.core.models import (
    ScanReport,
    PortListResult,
    BannerGrabResult,
    HTTPAnalysisResult,
    DiscoveryResult,
)

logger = get_logger(__name__)


class JSONReporter:
    """Generate JSON reports."""
    
    @staticmethod
    def report_scan(
        scan_report: ScanReport,
        output_file: Union[str, Path]
    ) -> Path:
        """Generate JSON scan report.
        
        Args:
            scan_report: ScanReport object
            output_file: Path to output JSON file
            
        Returns:
            Path to generated report
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dict and serialize
        report_dict = scan_report.model_dump(
            mode="json",
            exclude_none=True
        )
        
        # Add summary statistics
        if not report_dict.get("summary"):
            report_dict["summary"] = {
                "duration_seconds": scan_report.duration,
                "alive_hosts": scan_report.alive_hosts_count,
                "total_open_ports": scan_report.total_open_ports,
                "total_hosts_scanned": len(scan_report.hosts),
            }
        
        with open(output_path, "w") as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to {output_path}")
        return output_path
    
    @staticmethod
    def report_ports(
        port_result: PortListResult,
        output_file: Union[str, Path]
    ) -> Path:
        """Generate JSON port scan report.
        
        Args:
            port_result: PortListResult object
            output_file: Path to output JSON file
            
        Returns:
            Path to generated report
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        report_dict = port_result.model_dump(mode="json", exclude_none=True)
        
        with open(output_path, "w") as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        logger.info(f"Port scan report saved to {output_path}")
        return output_path
    
    @staticmethod
    def report_banners(
        banner_result: BannerGrabResult,
        output_file: Union[str, Path]
    ) -> Path:
        """Generate JSON banner grab report.
        
        Args:
            banner_result: BannerGrabResult object
            output_file: Path to output JSON file
            
        Returns:
            Path to generated report
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        report_dict = banner_result.model_dump(mode="json", exclude_none=True)
        
        with open(output_path, "w") as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        logger.info(f"Banner grab report saved to {output_path}")
        return output_path

    @staticmethod
    def report_http(
        http_result: HTTPAnalysisResult,
        output_file: Union[str, Path]
    ) -> Path:
        """Generate JSON HTTP/TLS analysis report."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report_dict = http_result.model_dump(mode="json", exclude_none=True)

        with open(output_path, "w") as f:
            json.dump(report_dict, f, indent=2, default=str)

        logger.info(f"HTTP analysis report saved to {output_path}")
        return output_path
    
    @staticmethod
    def report_discovery(
        discovery_result: DiscoveryResult,
        output_file: Union[str, Path]
    ) -> Path:
        """Generate JSON host discovery report.
        
        Args:
            discovery_result: DiscoveryResult object
            output_file: Path to output JSON file
            
        Returns:
            Path to generated report
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        report_dict = discovery_result.model_dump(mode="json", exclude_none=True)
        
        with open(output_path, "w") as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        logger.info(f"Discovery report saved to {output_path}")
        return output_path
