"""Target parsing and validation for ReconForge."""

import ipaddress
import socket
from typing import List, Set, Union

from reconforge.core.logging import get_logger

logger = get_logger(__name__)


class TargetParser:
    """Parse and validate reconnaissance targets."""
    
    @staticmethod
    def parse_target(target: str) -> List[str]:
        """Parse a target specification into individual IP addresses.
        
        Supports:
        - Single IPv4 address: 192.168.1.1
        - IPv4 CIDR range: 192.168.1.0/24
        - Hostname: example.com
        
        Args:
            target: Target specification (IP, CIDR, or hostname)
            
        Returns:
            List of IPv4 addresses to scan
            
        Raises:
            ValueError: If target format is invalid
        """
        target = target.strip()
        
        # Try to parse as CIDR network
        try:
            network = ipaddress.IPv4Network(target, strict=False)
            return [str(ip) for ip in network.hosts() or [network.network_address]]
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            pass
        
        # Try to parse as single IP address
        try:
            ip = ipaddress.IPv4Address(target)
            return [str(ip)]
        except (ipaddress.AddressValueError, ValueError):
            pass
        
        # Try to resolve as hostname
        try:
            resolved = socket.gethostbyname(target)
            logger.info(f"Resolved hostname '{target}' to {resolved}")
            return [resolved]
        except socket.gaierror as e:
            logger.warning(f"Failed to resolve hostname '{target}': {e}")
            raise ValueError(
                f"Invalid target '{target}'. Must be a valid IPv4 address, "
                f"CIDR range (e.g., 192.168.1.0/24), or hostname."
            )
    
    @staticmethod
    def parse_targets(targets: List[str]) -> Set[str]:
        """Parse multiple target specifications.
        
        Args:
            targets: List of target specifications
            
        Returns:
            Set of unique IPv4 addresses to scan
            
        Raises:
            ValueError: If any target is invalid
        """
        ips: Set[str] = set()
        
        for target in targets:
            try:
                ips.update(TargetParser.parse_target(target))
            except ValueError as e:
                logger.error(f"Error parsing target '{target}': {e}")
                raise
        
        logger.info(f"Parsed {len(ips)} unique targets from input")
        return ips
    
    @staticmethod
    def parse_ports(port_spec: Union[str, List[str]]) -> List[int]:
        """Parse port specification.
        
        Supports:
        - Comma-separated: 22,80,443
        - Range: 1-1024
        - Mixed: 22,80,443,1000-2000
        
        Args:
            port_spec: Port specification string or list
            
        Returns:
            List of port numbers
            
        Raises:
            ValueError: If port specification is invalid
        """
        if isinstance(port_spec, list):
            port_spec = ",".join(port_spec)
        
        ports: Set[int] = set()
        
        for part in port_spec.split(","):
            part = part.strip()
            
            # Range specification
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    
                    if start_port < 1 or end_port > 65535:
                        raise ValueError(f"Port range out of bounds: {part}")
                    if start_port > end_port:
                        raise ValueError(f"Invalid port range: {part}")
                    
                    ports.update(range(start_port, end_port + 1))
                except (ValueError, AttributeError) as e:
                    raise ValueError(f"Invalid port range '{part}': {e}")
            
            # Single port
            else:
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port out of range: {port}")
                    ports.add(port)
                except ValueError as e:
                    raise ValueError(f"Invalid port number '{part}': {e}")
        
        if not ports:
            raise ValueError("No valid ports specified")
        
        result = sorted(list(ports))
        logger.debug(f"Parsed {len(result)} ports from specification")
        return result
    
    @staticmethod
    def is_valid_ipv4(ip_str: str) -> bool:
        """Check if a string is a valid IPv4 address.
        
        Args:
            ip_str: String to validate
            
        Returns:
            True if valid IPv4 address, False otherwise
        """
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    @staticmethod
    def is_valid_cidr(cidr_str: str) -> bool:
        """Check if a string is a valid IPv4 CIDR range.
        
        Args:
            cidr_str: String to validate
            
        Returns:
            True if valid CIDR range, False otherwise
        """
        try:
            ipaddress.IPv4Network(cidr_str, strict=False)
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            return False
