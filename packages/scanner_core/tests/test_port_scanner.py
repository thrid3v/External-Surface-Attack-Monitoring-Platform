import pytest
from unittest.mock import patch, MagicMock
from scanner_core.port_scanner import scan_ports, _parse_nmap_output

def test_scan_ports_returns_list():
    """scan_ports always returns a list, never None."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {}
        mock_scanner.all_hosts.return_value = []
        mock_nmap.return_value = mock_scanner
        result = scan_ports("127.0.0.1", "80")
        assert isinstance(result, list)

def test_scan_ports_returns_empty_on_nmap_failure():
    """If nmap throws, return empty list — never crash."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_nmap.side_effect = Exception("nmap binary not found")
        result = scan_ports("127.0.0.1", "1-100")
        assert result == []

def test_scan_ports_only_returns_open_ports():
    """Closed and filtered ports must not appear in results."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ["192.168.1.1"]
        mock_scanner["192.168.1.1"].all_protocols.return_value = ["tcp"]
        mock_scanner["192.168.1.1"]["tcp"].keys.return_value = [22, 80, 443]
        mock_scanner["192.168.1.1"]["tcp"].__getitem__ = lambda self, port: {
            22:  {"state": "open",     "name": "ssh",   "product": "OpenSSH",   "version": "7.4", "extrainfo": ""},
            80:  {"state": "closed",   "name": "http",  "product": "",          "version": "",    "extrainfo": ""},
            443: {"state": "filtered", "name": "https", "product": "",          "version": "",    "extrainfo": ""},
        }[port]
        mock_nmap.return_value = mock_scanner
        result = scan_ports("192.168.1.1", "22,80,443")
        assert all(p.state == "open" for p in result)
        assert len(result) == 1
        assert result[0].port == 22

def test_scan_ports_maps_fields_correctly():
    """PortResult fields map correctly from nmap output."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ["192.168.1.1"]
        mock_scanner["192.168.1.1"].all_protocols.return_value = ["tcp"]
        mock_scanner["192.168.1.1"]["tcp"].keys.return_value = [80]
        mock_scanner["192.168.1.1"]["tcp"].__getitem__ = lambda self, port: {
            80: {"state": "open", "name": "http", "product": "Apache httpd",
                 "version": "2.4.51", "extrainfo": "Ubuntu"}
        }[port]
        mock_nmap.return_value = mock_scanner
        result = scan_ports("192.168.1.1", "80")
        assert len(result) == 1
        p = result[0]
        assert p.port == 80
        assert p.protocol == "tcp"
        assert p.product == "Apache httpd"
        assert p.version == "2.4.51"

def test_scan_ports_handles_missing_version_gracefully():
    """Ports with no version info should still return, version=None."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ["192.168.1.1"]
        mock_scanner["192.168.1.1"].all_protocols.return_value = ["tcp"]
        mock_scanner["192.168.1.1"]["tcp"].keys.return_value = [3306]
        mock_scanner["192.168.1.1"]["tcp"].__getitem__ = lambda self, port: {
            3306: {"state": "open", "name": "mysql", "product": "", "version": "", "extrainfo": ""}
        }[port]
        mock_nmap.return_value = mock_scanner
        result = scan_ports("192.168.1.1", "3306")
        assert result[0].version is None or result[0].version == ""

def test_scan_ports_default_port_range():
    """Calling without port_range should not throw."""
    with patch("nmap.PortScanner") as mock_nmap:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {}
        mock_scanner.all_hosts.return_value = []
        mock_nmap.return_value = mock_scanner
        result = scan_ports("127.0.0.1")
        assert isinstance(result, list)