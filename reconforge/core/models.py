"""Data models for ReconForge using Pydantic."""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field, ConfigDict


def _get_utc_now() -> datetime:
    """Get current UTC datetime (compatible with Python 3.9+)."""
    # Use timezone-aware approach for Python 3.9+ compatibility
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ScanConfig(BaseModel):
    """Configuration used for a scan."""
    
    model_config = ConfigDict(from_attributes=True)
    
    timeout: float = Field(default=2.0, description="Timeout in seconds")
    workers: int = Field(default=5, description="Number of worker threads")
    ports: List[int] = Field(default_factory=list, description="Ports to scan")
    ping_enabled: bool = Field(default=True, description="Enable ping discovery")


class BannerInfo(BaseModel):
    """Service banner information."""
    
    model_config = ConfigDict(from_attributes=True)
    
    port: int = Field(description="Port number")
    service: Optional[str] = Field(default=None, description="Service name (if known)")
    banner: Optional[str] = Field(default=None, description="Raw banner text")
    http_headers: Optional[Dict[str, str]] = Field(default=None, description="HTTP response headers")
    timestamp: datetime = Field(default_factory=_get_utc_now, description="Time of banner grab")


class PortScanResult(BaseModel):
    """Result of a single port scan."""
    
    model_config = ConfigDict(from_attributes=True)
    
    port: int = Field(description="Port number")
    open: bool = Field(description="Whether port is open")
    service: Optional[str] = Field(default=None, description="Known service name")
    banner: Optional[BannerInfo] = Field(default=None, description="Banner information if available")


class HostInfo(BaseModel):
    """Information about a discovered host."""
    
    model_config = ConfigDict(from_attributes=True)
    
    ip_address: str = Field(description="IPv4 address of the host")
    hostname: Optional[str] = Field(default=None, description="Hostname if resolved")
    alive: bool = Field(description="Whether host is alive (ping response)")
    open_ports: List[PortScanResult] = Field(default_factory=list, description="Open ports found")
    timestamp: datetime = Field(default_factory=_get_utc_now, description="Time of discovery")


class ScanReport(BaseModel):
    """Complete scan report."""
    
    model_config = ConfigDict(from_attributes=True)
    
    scan_id: str = Field(description="Unique scan identifier")
    target: str = Field(description="Original target specification")
    targets_scanned: List[str] = Field(description="Actual targets scanned")
    start_time: datetime = Field(description="Scan start time")
    end_time: datetime = Field(description="Scan end time")
    scan_config: ScanConfig = Field(description="Configuration used for scan")
    hosts: List[HostInfo] = Field(default_factory=list, description="Discovered hosts and their info")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Summary statistics")
    
    @property
    def duration(self) -> float:
        """Get scan duration in seconds."""
        return (self.end_time - self.start_time).total_seconds()
    
    @property
    def alive_hosts_count(self) -> int:
        """Get count of alive hosts."""
        return sum(1 for host in self.hosts if host.alive)
    
    @property
    def total_open_ports(self) -> int:
        """Get total count of open ports across all hosts."""
        return sum(
            len([p for p in host.open_ports if p.open])
            for host in self.hosts
        )


class BannerGrabResult(BaseModel):
    """Result of banner grabbing operations."""
    
    model_config = ConfigDict(from_attributes=True)
    
    target: str = Field(description="Target host")
    ports: List[BannerInfo] = Field(default_factory=list, description="Banners from each port")
    timestamp: datetime = Field(default_factory=_get_utc_now, description="Time of operation")


class TLSCertificateInfo(BaseModel):
    """TLS certificate metadata collected from a server."""

    model_config = ConfigDict(from_attributes=True)

    subject: Optional[str] = Field(default=None, description="Certificate subject")
    issuer: Optional[str] = Field(default=None, description="Certificate issuer")
    not_before: Optional[str] = Field(default=None, description="Certificate validity start")
    not_after: Optional[str] = Field(default=None, description="Certificate validity end")
    sans: List[str] = Field(default_factory=list, description="Subject alternative names")
    error: Optional[str] = Field(default=None, description="TLS inspection error, if any")


class HTTPAnalysisResult(BaseModel):
    """Passive HTTP/TLS configuration analysis result."""

    model_config = ConfigDict(from_attributes=True)

    target: str = Field(description="Target host")
    port: int = Field(description="Target port")
    scheme: str = Field(description="HTTP scheme used")
    status_code: Optional[int] = Field(default=None, description="HTTP status code")
    server_header: Optional[str] = Field(default=None, description="Server response header")
    security_headers: Dict[str, Optional[str]] = Field(
        default_factory=dict,
        description="Selected HTTP security headers",
    )
    redirects: List[str] = Field(default_factory=list, description="Observed redirect locations")
    tls_certificate: Optional[TLSCertificateInfo] = Field(
        default=None,
        description="TLS certificate metadata for HTTPS targets",
    )
    error: Optional[str] = Field(default=None, description="HTTP analysis error, if any")
    timestamp: datetime = Field(default_factory=_get_utc_now, description="Time of analysis")


class DiscoveryResult(BaseModel):
    """Result of host discovery."""
    
    model_config = ConfigDict(from_attributes=True)
    
    target_range: str = Field(description="Target network range")
    alive_hosts: List[str] = Field(description="IPv4 addresses of alive hosts")
    dead_hosts: List[str] = Field(description="IPv4 addresses of dead/unresponsive hosts")
    timestamp: datetime = Field(default_factory=_get_utc_now, description="Time of discovery")


class PortListResult(BaseModel):
    """Result of port scanning a single host."""
    
    model_config = ConfigDict(from_attributes=True)
    
    target: str = Field(description="Target host")
    open_ports: List[PortScanResult] = Field(description="Open ports found")
    scanned_ports: List[int] = Field(description="All ports that were scanned")
    timestamp: datetime = Field(default_factory=_get_utc_now, description="Time of scan")
