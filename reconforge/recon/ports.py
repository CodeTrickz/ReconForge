"""TCP port scanning module for ReconForge."""

import asyncio
from typing import List, Optional

from reconforge.core.config import DEFAULT_PORTS
from reconforge.core.logging import get_logger
from reconforge.core.models import PortScanResult, PortListResult

logger = get_logger(__name__)


class PortScanner:
    """Scan TCP ports using bounded asynchronous TCP connect calls."""
    
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
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        self.timeout = timeout

    @staticmethod
    def _validate_host(host: str) -> None:
        if not isinstance(host, str) or not host.strip():
            raise ValueError("Host must be a non-empty string")

    @staticmethod
    def _validate_workers(workers: int) -> None:
        if workers < 1:
            raise ValueError("Workers must be at least 1")

    @staticmethod
    def _normalize_ports(ports: Optional[List[int]]) -> List[int]:
        if ports is None:
            ports = DEFAULT_PORTS

        normalized = sorted(set(ports))
        for port in normalized:
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}. Use ports in range 1-65535.")
        return normalized
    
    async def _scan_port_async(
        self,
        host: str,
        port: int,
        semaphore: asyncio.Semaphore,
    ) -> PortScanResult:
        """Scan a single port on a host with an async TCP connect.
        
        Args:
            host: Target IP address
            port: Port number to scan
            semaphore: Concurrency limiter
            
        Returns:
            PortScanResult with scan results
        """
        result = PortScanResult(
            port=port,
            open=False,
            service=self.SERVICE_PORTS.get(port),
        )

        async with semaphore:
            writer = None
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout,
                )
                result.open = True
                logger.debug(f"Port {port} on {host} is open")
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                result.open = False
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

        return result

    async def _scan_async(self, host: str, ports: List[int], workers: int) -> List[PortScanResult]:
        """Scan ports asynchronously using bounded concurrency."""
        semaphore = asyncio.Semaphore(min(workers, len(ports)))
        tasks = [
            self._scan_port_async(host, port, semaphore)
            for port in ports
        ]
        return await asyncio.gather(*tasks)
    
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
        self._validate_host(host)
        self._validate_workers(workers)
        ports = self._normalize_ports(ports)
        logger.info(f"Scanning {len(ports)} ports on {host}")
        
        if not ports:
            return PortListResult(
                target=host,
                open_ports=[],
                scanned_ports=[],
            )

        results = asyncio.run(self._scan_async(host, ports, workers))
        open_ports = [result for result in results if result.open]
        
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
