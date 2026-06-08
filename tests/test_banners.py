"""Unit tests for banner grabbing module."""

import pytest

from reconforge.recon.banners import BannerGrabber, HTTP_PORTS


class TestBannerGrabber:
    """Test BannerGrabber class."""
    
    @pytest.fixture
    def grabber(self):
        """Create a banner grabber instance."""
        return BannerGrabber(timeout=1.0)
    
    def test_grabber_initialization(self, grabber):
        """Test grabber initializes correctly."""
        assert grabber.timeout == 1.0
    
    def test_grabber_http_ports(self, grabber):
        """Test HTTP port detection."""
        assert 80 in HTTP_PORTS
        assert 443 in HTTP_PORTS
        assert 8080 in HTTP_PORTS
    
    def test_grab_banner_invalid_host(self, grabber):
        """Test banner grab with invalid host."""
        result = grabber.grab_banner("invalid.host.invalid", 22)
        assert result is None
    
    def test_grab_banners_returns_result(self, grabber):
        """Test grab_banners returns BannerGrabResult."""
        result = grabber.grab_banners("127.0.0.1", [22])
        assert result.target == "127.0.0.1"
        assert isinstance(result.ports, list)
    
    def test_grab_multiple_banners(self, grabber):
        """Test grabbing from multiple ports."""
        result = grabber.grab_banners("127.0.0.1", [22, 80, 443])
        assert result.target == "127.0.0.1"
        # Result should have attempted all ports
        assert len(result.ports) <= 3


class TestBannerGrabberHTTP:
    """Test HTTP banner grabbing functionality."""
    
    @pytest.fixture
    def grabber(self):
        """Create a banner grabber instance."""
        return BannerGrabber(timeout=0.5)
    
    def test_http_banner_has_headers(self, grabber):
        """Test HTTP banner includes headers when available."""
        result = grabber.grab_banner("127.0.0.1", 80)
        if result:
            # HTTP banners may have headers
            assert hasattr(result, 'http_headers')


class TestBannerGrabberConfiguration:
    """Test banner grabber configuration."""
    
    def test_custom_timeout(self):
        """Test grabber with custom timeout."""
        grabber = BannerGrabber(timeout=5.0)
        assert grabber.timeout == 5.0
    
    def test_default_timeout(self):
        """Test grabber with default timeout."""
        grabber = BannerGrabber()
        assert grabber.timeout == 2.0
    
    def test_worker_configuration(self):
        """Test workers parameter in grab_banners."""
        grabber = BannerGrabber(timeout=1.0)
        result = grabber.grab_banners("127.0.0.1", [22], workers=3)
        assert result.target == "127.0.0.1"


class TestBannerGrabberEdgeCases:
    """Test edge cases in banner grabbing."""
    
    @pytest.fixture
    def grabber(self):
        """Create a banner grabber instance."""
        return BannerGrabber(timeout=0.5)
    
    def test_grab_empty_port_list(self, grabber):
        """Test grabbing from empty port list."""
        result = grabber.grab_banners("127.0.0.1", [])
        assert result.target == "127.0.0.1"
        assert len(result.ports) == 0
    
    def test_grab_single_port(self, grabber):
        """Test grabbing from single port."""
        result = grabber.grab_banners("127.0.0.1", [22])
        assert result.target == "127.0.0.1"
