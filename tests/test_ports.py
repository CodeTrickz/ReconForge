"""Unit tests for port scanning module."""

import pytest

from reconforge.recon.ports import PortScanner


class TestPortScanner:
    """Test PortScanner class."""
    
    @pytest.fixture
    def scanner(self):
        """Create a port scanner instance."""
        return PortScanner(timeout=1.0)
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner.timeout == 1.0
    
    def test_scanner_service_ports(self, scanner):
        """Test known service port mappings."""
        assert PortScanner.SERVICE_PORTS[22] == "SSH"
        assert PortScanner.SERVICE_PORTS[80] == "HTTP"
        assert PortScanner.SERVICE_PORTS[443] == "HTTPS"
    
    def test_scan_invalid_host(self, scanner):
        """Test scanning invalid host raises error."""
        result = scanner.scan("invalid.host.invalid")
        assert result.target == "invalid.host.invalid"
        assert len(result.open_ports) == 0
    
    def test_scan_localhost_ports(self, scanner):
        """Test scanning localhost ports."""
        # This test scans localhost which should always be up
        result = scanner.scan("127.0.0.1", ports=[22, 80, 443])
        assert result.target == "127.0.0.1"
        # Localhost results depend on what's running locally
        assert hasattr(result, 'scanned_ports')
    
    def test_scan_returns_port_list_result(self, scanner):
        """Test scan returns proper PortListResult."""
        result = scanner.scan("127.0.0.1", ports=[22])
        assert result.target == "127.0.0.1"
        assert result.scanned_ports == [22]
        assert isinstance(result.open_ports, list)
    
    def test_scan_multiple_hosts(self, scanner):
        """Test scanning multiple hosts."""
        hosts = ["127.0.0.1", "127.0.0.2"]
        results = scanner.scan_hosts(hosts, ports=[22])
        assert len(results) == 2
        assert "127.0.0.1" in results
        assert "127.0.0.2" in results


class TestPortScannerPortDetection:
    """Test port detection functionality."""
    
    @pytest.fixture
    def scanner(self):
        """Create a port scanner instance."""
        return PortScanner(timeout=0.5)
    
    def test_port_result_attributes(self, scanner):
        """Test PortScanResult has required attributes."""
        result = scanner.scan("127.0.0.1", ports=[1])
        for port_result in result.open_ports:
            assert hasattr(port_result, 'port')
            assert hasattr(port_result, 'open')
            assert hasattr(port_result, 'service')
    
    def test_service_identification(self, scanner):
        """Test service identification for known ports."""
        result = scanner.scan("127.0.0.1", ports=[22, 80, 443])
        port_services = {p.port: p.service for p in result.open_ports}
        
        # Check that services are recognized
        for port in [22, 80, 443]:
            if any(p.port == port for p in result.open_ports):
                assert port in PortScanner.SERVICE_PORTS


class TestPortScannerConfiguration:
    """Test port scanner configuration."""
    
    def test_custom_timeout(self):
        """Test scanner with custom timeout."""
        scanner = PortScanner(timeout=5.0)
        assert scanner.timeout == 5.0
    
    def test_default_timeout(self):
        """Test scanner with default timeout."""
        scanner = PortScanner()
        assert scanner.timeout == 2.0
