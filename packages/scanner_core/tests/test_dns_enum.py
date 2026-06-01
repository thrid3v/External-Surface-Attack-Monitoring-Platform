import pytest
from unittest.mock import patch, MagicMock
from scanner_core.dns_enum import (
    get_dns_records, enumerate_subdomains,
    check_zone_transfer, run_dns_enum
)

def test_get_dns_records_returns_list():
    """get_dns_records always returns a list."""
    with patch("dns.resolver.resolve") as mock_resolve:
        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([]))
        mock_resolve.return_value = mock_answer
        result = get_dns_records("example.com")
        assert isinstance(result, list)

def test_get_dns_records_returns_empty_on_nxdomain():
    """NXDOMAIN should return empty list, not raise."""
    import dns.resolver
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN):
        result = get_dns_records("thisdoesnotexist99999.com")
        assert result == []

def test_get_dns_records_returns_empty_on_timeout():
    """DNS timeout should return empty list, not raise."""
    import dns.resolver
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoNameservers):
        result = get_dns_records("example.com")
        assert result == []

def test_get_dns_records_maps_record_type():
    """Returned DNSRecord objects should have correct record_type."""
    import dns.resolver
    mock_rdata = MagicMock()
    mock_rdata.__str__ = lambda self: "93.184.216.34"
    mock_answer = [mock_rdata]

    def fake_resolve(domain, record_type):
        if record_type == "A":
            return mock_answer
        raise dns.resolver.NoAnswer

    with patch("dns.resolver.resolve", side_effect=fake_resolve):
        result = get_dns_records("example.com")
        a_records = [r for r in result if r.record_type == "A"]
        assert len(a_records) >= 1

def test_enumerate_subdomains_returns_list():
    """enumerate_subdomains always returns a list."""
    with patch("dns.resolver.resolve", side_effect=Exception("no resolve")):
        result = enumerate_subdomains("example.com")
        assert isinstance(result, list)

def test_enumerate_subdomains_only_returns_resolved():
    """Only subdomains that actually resolve should be returned."""
    import dns.resolver

    def fake_resolve(domain, record_type="A"):
        if domain == "www.example.com":
            mock_rdata = MagicMock()
            mock_rdata.__str__ = lambda self: "93.184.216.34"
            return [mock_rdata]
        raise dns.resolver.NXDOMAIN

    with patch("dns.resolver.resolve", side_effect=fake_resolve):
        result = enumerate_subdomains("example.com")
        assert all(hasattr(r, "subdomain") for r in result)
        fqdns = [r.subdomain for r in result]
        assert all("example.com" in s for s in fqdns)

def test_check_zone_transfer_returns_false_when_rejected():
    """Most servers reject AXFR — should return False cleanly."""
    import dns.query, dns.zone
    with patch("dns.query.xfr", side_effect=Exception("REFUSED")):
        with patch("dns.resolver.resolve") as mock_ns:
            mock_rdata = MagicMock()
            mock_rdata.target.__str__ = lambda self: "ns1.example.com"
            mock_ns.return_value = [mock_rdata]
            result = check_zone_transfer("example.com")
            assert result is False

def test_run_dns_enum_never_raises():
    """run_dns_enum should return a dict even if all DNS calls fail."""
    with patch("scanner_core.dns_enum.get_dns_records", return_value=[]), \
         patch("scanner_core.dns_enum.enumerate_subdomains", return_value=[]), \
         patch("scanner_core.dns_enum.check_zone_transfer", return_value=False):
        result = run_dns_enum("example.com")
        assert isinstance(result, dict)
        assert "dns_records" in result
        assert "subdomains" in result
        assert "zone_transfer_vulnerable" in result

def test_run_dns_enum_zone_transfer_finding_is_flagged():
    """If zone transfer succeeds, it must be flagged in the result."""
    with patch("scanner_core.dns_enum.get_dns_records", return_value=[]), \
         patch("scanner_core.dns_enum.enumerate_subdomains", return_value=[]), \
         patch("scanner_core.dns_enum.check_zone_transfer", return_value=["internal.example.com"]):
        result = run_dns_enum("example.com")
        assert result["zone_transfer_vulnerable"] is True