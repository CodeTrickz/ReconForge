"""Host discovery module for ReconForge using ping sweep."""

import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

from reconforge.core.logging import get_logger
from reconforge.core.models import DiscoveryResult

logger = get_logger(__name__)


class HostDiscovery:
    """Discover live hosts using ping sweep."""
    
    def __init__(self, timeout: float = 2.0):
        """Initialize host discovery.
        
        Args:
            timeout: Timeout in seconds for each ping
        """
        self.timeout = timeout
        self.os_type = platform.system()
    
    def _get_ping_command(self, host: str) -> List[str]:
        """Get platform-specific ping command.
        
        Args:
            host: Target host IP address
            
        Returns:
            Command list for subprocess.run()
        """
        if self.os_type == "Windows":
            # Windows ping: -n (count) -w (timeout in ms)
            return ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), host]
        else:
            # Linux/macOS ping: -c (count) -W (timeout in seconds)
            # On macOS: -W for timeout, on Linux: -W as well
            return ["ping", "-c", "1", "-W", str(int(self.timeout)), host]
    
    def _ping_host(self, host: str) -> bool:
        """Ping a single host.
        
        Args:
            host: Target host IP address
            
        Returns:
            True if host responds, False otherwise
        """
        try:
            cmd = self._get_ping_command(host)
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout + 1,
                text=True
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, Exception) as e:
            logger.debug(f"Ping to {host} failed: {e}")
            return False
    
    def discover(self, hosts: List[str], workers: int = 5) -> DiscoveryResult:
        """Discover live hosts using parallel ping sweep.
        
        Args:
            hosts: List of IP addresses to ping
            workers: Number of worker threads
            
        Returns:
            DiscoveryResult with alive and dead hosts
        """
        target_range = f"{len(hosts)} hosts"
        if hosts and len(hosts) <= 5:
            target_range = ", ".join(hosts)
        
        logger.info(f"Starting host discovery on {target_range}")
        
        alive_hosts: List[str] = []
        dead_hosts: List[str] = []

        if not hosts:
            return DiscoveryResult(
                target_range=target_range,
                alive_hosts=[],
                dead_hosts=[],
            )
        
        with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as executor:
            # Submit all ping tasks
            futures = {
                executor.submit(self._ping_host, host): host
                for host in hosts
            }
            
            # Collect results
            for future in as_completed(futures):
                host = futures[future]
                try:
                    if future.result():
                        alive_hosts.append(host)
                        logger.debug(f"Host {host} is alive")
                    else:
                        dead_hosts.append(host)
                except Exception as e:
                    logger.error(f"Error pinging {host}: {e}")
                    dead_hosts.append(host)
        
        logger.info(
            f"Discovery complete: {len(alive_hosts)} alive, {len(dead_hosts)} dead"
        )
        
        return DiscoveryResult(
            target_range=target_range,
            alive_hosts=sorted(alive_hosts),
            dead_hosts=sorted(dead_hosts),
        )
