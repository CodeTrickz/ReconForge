"""TCP port scanning module for ReconForge."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from reconforge.core.config import DEFAULT_PORTS
from reconforge.core.logging import get_logger
from reconforge.core.models import PortScanResult, PortListResult

logger = get_logger(__name__)


class PortScanner:
    """Scan TCP ports using socket connect."""
    
    # Common service port mappings
    SERVICE_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
        6379: "Redis",
        5900: "VNC",
    }
    
    def __init__(self, timeout: float = 2.0):
        """Initialize port scanner.
        
        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
    
    def _scan_port(self, host: str, port: int) -> PortScanResult:
        """Scan a single port on a host.
        
        Args:
            host: Target IP address
            port: Port number to scan
            
        Returns:
            PortScanResult with scan results
        """
        result = PortScanResult(
            port=port,
            open=False,
            service=self.SERVICE_PORTS.get(port),
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                # Attempt TCP connection
                sock.connect((host, port))
                result.open = True
                logger.debug(f"Port {port} on {host} is open")
            except (socket.timeout, ConnectionRefusedError, OSError):
                result.open = False
            finally:
                sock.close()
        
        except Exception as e:
            logger.debug(f"Error scanning {host}:{port}: {e}")
            result.open = False
        
        return result
    
    def scan(
        self,
        host: str,
        ports: Optional[List[int]] = None,
        workers: int = 5
    ) -> PortListResult:
        """Scan multiple ports on a host.
        
        Args:
            host: Target IP address
            ports: List of ports to scan (default: common ports)
            workers: Number of worker threads
            
        Returns:
            PortListResult with all scan results
        """
        if ports is None:
            ports = DEFAULT_PORTS
        
        ports = sorted(set(ports))  # Remove duplicates and sort
        logger.info(f"Scanning {len(ports)} ports on {host}")
        
        open_ports: List[PortScanResult] = []

        if not ports:
            return PortListResult(
                target=host,
                open_ports=[],
                scanned_ports=[],
            )
        
        with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as executor:
            # Submit all scan tasks
            futures = {
                executor.submit(self._scan_port, host, port): port
                for port in ports
            }
            
            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result.open:
                        open_ports.append(result)
                except Exception as e:
                    port = futures[future]
                    logger.error(f"Error scanning port {port}: {e}")
        
        logger.info(f"Found {len(open_ports)} open ports on {host}")
        
        return PortListResult(
            target=host,
            open_ports=sorted(open_ports, key=lambda p: p.port),
            scanned_ports=ports,
        )
    
    def scan_hosts(
        self,
        hosts: List[str],
        ports: Optional[List[int]] = None,
        workers: int = 5
    ) -> dict:
        """Scan multiple hosts.
        
        Args:
            hosts: List of target IP addresses
            ports: List of ports to scan
            workers: Number of worker threads per host
            
        Returns:
            Dictionary mapping host to PortListResult
        """
        results = {}
        
        for host in hosts:
            try:
                results[host] = self.scan(host, ports, workers)
            except Exception as e:
                logger.error(f"Error scanning host {host}: {e}")
        
        return results
