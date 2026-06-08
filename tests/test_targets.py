"""Unit tests for target parsing module."""

import pytest

from reconforge.core.targets import TargetParser


class TestTargetParser:
    """Test TargetParser class."""
    
    def test_parse_single_ipv4(self):
        """Test parsing single IPv4 address."""
        result = TargetParser.parse_target("192.168.1.1")
        assert result == ["192.168.1.1"]
    
    def test_parse_cidr_network(self):
        """Test parsing CIDR network notation."""
        result = TargetParser.parse_target("192.168.1.0/30")
        # /30 network has 4 addresses, .0 is network, .3 is broadcast
        assert len(result) == 2  # Should have .1 and .2 (hosts)
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
    
    def test_parse_invalid_target(self):
        """Test parsing invalid target raises error."""
        with pytest.raises(ValueError):
            TargetParser.parse_target("invalid")
    
    def test_parse_multiple_targets(self):
        """Test parsing multiple targets."""
        targets = ["192.168.1.1", "192.168.1.0/30"]
        result = TargetParser.parse_targets(targets)
        assert "192.168.1.1" in result
        assert isinstance(result, set)
    
    def test_parse_ports_single(self):
        """Test parsing single port."""
        result = TargetParser.parse_ports("22")
        assert result == [22]
    
    def test_parse_ports_multiple(self):
        """Test parsing multiple ports."""
        result = TargetParser.parse_ports("22,80,443")
        assert set(result) == {22, 80, 443}
    
    def test_parse_ports_range(self):
        """Test parsing port range."""
        result = TargetParser.parse_ports("80-82")
        assert result == [80, 81, 82]
    
    def test_parse_ports_mixed(self):
        """Test parsing mixed port specification."""
        result = TargetParser.parse_ports("22,80-82,443")
        assert set(result) == {22, 80, 81, 82, 443}
    
    def test_parse_ports_invalid_range(self):
        """Test invalid port range raises error."""
        with pytest.raises(ValueError):
            TargetParser.parse_ports("443-22")  # End before start
    
    def test_parse_ports_out_of_bounds(self):
        """Test ports out of valid range raise error."""
        with pytest.raises(ValueError):
            TargetParser.parse_ports("70000")
    
    def test_is_valid_ipv4(self):
        """Test IPv4 validation."""
        assert TargetParser.is_valid_ipv4("192.168.1.1") is True
        assert TargetParser.is_valid_ipv4("256.1.1.1") is False
        assert TargetParser.is_valid_ipv4("not-an-ip") is False
    
    def test_is_valid_cidr(self):
        """Test CIDR validation."""
        assert TargetParser.is_valid_cidr("192.168.1.0/24") is True
        assert TargetParser.is_valid_cidr("192.168.1.1/33") is False
        assert TargetParser.is_valid_cidr("not-cidr") is False


class TestTargetParserEdgeCases:
    """Test edge cases in target parsing."""
    
    def test_parse_single_host_cidr(self):
        """Test parsing /32 CIDR (single host)."""
        result = TargetParser.parse_target("192.168.1.1/32")
        assert "192.168.1.1" in result
    
    def test_parse_ports_empty_spec(self):
        """Test empty port specification."""
        with pytest.raises(ValueError):
            TargetParser.parse_ports("")
    
    def test_parse_ports_whitespace(self):
        """Test ports with whitespace."""
        result = TargetParser.parse_ports("22, 80, 443")
        assert set(result) == {22, 80, 443}
    
    def test_parse_ports_duplicates(self):
        """Test duplicate ports are deduplicated."""
        result = TargetParser.parse_ports("22,22,80,80")
        assert result == [22, 80]
    
    def test_parse_targets_deduplication(self):
        """Test targets are deduplicated."""
        targets = ["192.168.1.1", "192.168.1.1"]
        result = TargetParser.parse_targets(targets)
        assert len(result) == 1
