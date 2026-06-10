"""Banner grabbing module for ReconForge."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from reconforge.core.logging import get_logger
from reconforge.core.models import BannerInfo, BannerGrabResult

logger = get_logger(__name__)

# HTTP-based ports that should use HTTP HEAD request
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888}
MAX_BANNER_BYTES = 8192


class BannerGrabber:
    """Grab service banners for identification."""
    
    def __init__(self, timeout: float = 2.0):
        """Initialize banner grabber.
        
        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout
    
    def _grab_http_banner(self, host: str, port: int) -> Optional[BannerInfo]:
        """Grab banner from HTTP service using HEAD request.
        
        Args:
            host: Target IP address
            port: Port number
            
        Returns:
            BannerInfo with HTTP headers or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((host, port))
                
                # Send HTTP HEAD request
                request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode())
                
                # Receive response
                response = b""
                deadline = time.monotonic() + self.timeout
                while len(response) < MAX_BANNER_BYTES and time.monotonic() < deadline:
                    try:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        response += chunk
                    except socket.timeout:
                        break
                
                response_str = response.decode(errors="ignore")
                
                # Parse headers
                headers: Dict[str, str] = {}
                status_line = ""
                
                for line in response_str.split("\r\n"):
                    if not status_line and line.startswith("HTTP"):
                        status_line = line
                    elif ": " in line:
                        key, value = line.split(": ", 1)
                        headers[key.strip()] = value.strip()
                
                banner_text = status_line or response_str[:200]
                
                return BannerInfo(
                    port=port,
                    service="HTTP",
                    banner=banner_text,
                    http_headers=headers if headers else None,
                )
            
            finally:
                sock.close()
        
        except Exception as e:
            logger.debug(f"HTTP banner grab failed for {host}:{port}: {e}")
            return None
    
    def _grab_raw_banner(self, host: str, port: int) -> Optional[BannerInfo]:
        """Grab banner by reading initial data from socket.
        
        Args:
            host: Target IP address
            port: Port number
            
        Returns:
            BannerInfo with banner or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((host, port))
                
                # Try to receive initial banner without sending anything
                banner = b""
                try:
                    banner = sock.recv(1024)
                except socket.timeout:
                    pass
                
                if banner:
                    banner_str = banner.decode(errors="ignore").strip()
                    return BannerInfo(
                        port=port,
                        banner=banner_str,
                    )
            
            finally:
                sock.close()
        
        except Exception as e:
            logger.debug(f"Raw banner grab failed for {host}:{port}: {e}")
        
        return None
    
    def grab_banner(self, host: str, port: int) -> Optional[BannerInfo]:
        """Grab banner from a service.
        
        Args:
            host: Target IP address
            port: Port number
            
        Returns:
            BannerInfo with service information or None
        """
        # Try HTTP-specific grabbing for HTTP ports
        if port in HTTP_PORTS:
            result = self._grab_http_banner(host, port)
            if result and result.banner:
                logger.debug(f"Grabbed HTTP banner from {host}:{port}")
                return result
        
        # Fall back to raw banner grabbing
        result = self._grab_raw_banner(host, port)
        if result:
            logger.debug(f"Grabbed raw banner from {host}:{port}")
        
        return result
    
    def grab_banners(
        self,
        host: str,
        ports: List[int],
        workers: int = 5
    ) -> BannerGrabResult:
        """Grab banners from multiple ports.
        
        Args:
            host: Target IP address
            ports: List of ports to grab banners from
            workers: Number of worker threads
            
        Returns:
            BannerGrabResult with all banners
        """
        logger.info(f"Grabbing banners from {len(ports)} ports on {host}")
        
        banners: List[BannerInfo] = []
        
        # Handle empty port list
        if not ports:
            return BannerGrabResult(target=host, ports=[])
        
        with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as executor:
            futures = {
                executor.submit(self.grab_banner, host, port): port
                for port in ports
            }
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        banners.append(result)
                except Exception as e:
                    port = futures[future]
                    logger.error(f"Error grabbing banner from {host}:{port}: {e}")
        
        logger.info(f"Grabbed {len(banners)} banners from {host}")
        
        return BannerGrabResult(
            target=host,
            ports=sorted(banners, key=lambda b: b.port),
        )
