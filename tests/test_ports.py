"""Unit tests for port scanning module."""

import asyncio
import socket
import socketserver
import threading

import pytest

from reconforge.recon.ports import PortScanner


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(1)


class _ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


@pytest.fixture
def open_tcp_port():
    server = _ReusableTCPServer(("127.0.0.1", 0), _TCPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def closed_tcp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


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

    def test_scan_detects_open_port(self, scanner, open_tcp_port):
        """Test scanning detects a locally opened TCP port."""
        result = scanner.scan("127.0.0.1", ports=[open_tcp_port])

        assert result.scanned_ports == [open_tcp_port]
        assert [port.port for port in result.open_ports] == [open_tcp_port]

    def test_scan_detects_closed_port(self, scanner, closed_tcp_port):
        """Test scanning treats connection-refused ports as closed."""
        result = scanner.scan("127.0.0.1", ports=[closed_tcp_port])

        assert result.scanned_ports == [closed_tcp_port]
        assert result.open_ports == []

    def test_scan_timeout_handling(self, monkeypatch):
        """Test timed out connections are reported as closed."""
        scanner = PortScanner(timeout=0.01)

        async def slow_open_connection(host, port):
            await asyncio.sleep(1)

        monkeypatch.setattr("reconforge.recon.ports.asyncio.open_connection", slow_open_connection)

        result = scanner.scan("127.0.0.1", ports=[12345])

        assert result.open_ports == []

    def test_scan_uses_bounded_concurrency(self, monkeypatch):
        """Test async connection attempts respect the worker bound."""
        scanner = PortScanner(timeout=1)
        active = 0
        max_active = 0

        async def fake_open_connection(host, port):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0.01)
            active -= 1
            raise ConnectionRefusedError

        monkeypatch.setattr("reconforge.recon.ports.asyncio.open_connection", fake_open_connection)

        scanner.scan("127.0.0.1", ports=[1001, 1002, 1003, 1004, 1005], workers=2)

        assert max_active <= 2

    def test_scan_rejects_invalid_input(self, scanner):
        """Test scanner rejects invalid host, port, workers, and timeout."""
        with pytest.raises(ValueError, match="Host"):
            scanner.scan("", ports=[80])
        with pytest.raises(ValueError, match="Invalid port"):
            scanner.scan("127.0.0.1", ports=[0])
        with pytest.raises(ValueError, match="Workers"):
            scanner.scan("127.0.0.1", ports=[80], workers=0)
        with pytest.raises(ValueError, match="Timeout"):
            PortScanner(timeout=0)
    
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
