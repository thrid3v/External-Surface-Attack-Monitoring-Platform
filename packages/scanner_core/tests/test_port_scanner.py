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


# --- two-phase scan (fast discovery, then -sV only on open ports) ------------

def test_two_phase_runs_version_detection_only_on_open_ports():
    """Discovery (no -sV) finds open ports; version detection then runs on just
    those ports, so -sV never sweeps the full range and blows the host-timeout."""
    disc = {"scan": {"t": {"tcp": {
        80: {"state": "open", "name": "http"},
        443: {"state": "open", "name": "https"},
        22: {"state": "closed", "name": "ssh"},
    }}}}
    ver = {"scan": {"t": {"tcp": {
        80: {"state": "open", "name": "http", "product": "nginx", "version": "1.20"},
        443: {"state": "open", "name": "https", "product": "nginx", "version": "1.20"},
    }}}}
    with patch("nmap.PortScanner") as mock_nmap:
        scanner = MagicMock()
        scanner.scan.side_effect = [disc, ver]
        mock_nmap.return_value = scanner
        result = scan_ports("t", "1-1000")

        calls = scanner.scan.call_args_list
        assert "-sV" not in calls[0].kwargs.get("arguments", "")  # discovery is fast
        assert "-sV" in calls[1].kwargs.get("arguments", "")       # version phase
        assert calls[1].kwargs.get("ports") == "80,443"            # only open ports
        assert {p.port for p in result} == {80, 443}
        assert all(p.product == "nginx" for p in result)


def test_no_version_scan_when_no_open_ports():
    """A clean host (0 open ports, scan completed quickly) returns [] without a
    second nmap invocation."""
    disc = {"scan": {"t": {"tcp": {80: {"state": "closed"}}}},
            "nmap": {"scanstats": {"elapsed": "3.0"}}}
    with patch("nmap.PortScanner") as mock_nmap:
        scanner = MagicMock()
        scanner.scan.return_value = disc
        mock_nmap.return_value = scanner
        result = scan_ports("t", "1-1000")
        assert result == []
        assert scanner.scan.call_count == 1


def test_version_phase_failure_keeps_discovered_ports():
    """If version detection times out / returns nothing, the open ports found by
    discovery must still be reported (enrichment failing != ports disappearing)."""
    disc = {"scan": {"t": {"tcp": {
        80: {"state": "open", "name": "http"},
        443: {"state": "open", "name": "https"},
    }}}}
    ver_empty = {"scan": {"t": {"tcp": {}}}}  # nmap aborted -sV, parsed nothing
    with patch("nmap.PortScanner") as mock_nmap:
        scanner = MagicMock()
        scanner.scan.side_effect = [disc, ver_empty]
        mock_nmap.return_value = scanner
        result = scan_ports("t", "1-1000")
        assert {p.port for p in result} == {80, 443}


def test_host_timeout_with_no_ports_raises_incomplete():
    """When nmap burns its whole host-timeout and finds nothing, that's an
    unreliable scan — raise so the caller records an error instead of scoring 0."""
    from scanner_core.port_scanner import PortScanIncompleteError, DISCOVERY_TIMEOUT_SECONDS

    disc = {"scan": {"t": {"tcp": {}}},
            "nmap": {"scanstats": {"elapsed": str(DISCOVERY_TIMEOUT_SECONDS)}}}
    with patch("nmap.PortScanner") as mock_nmap:
        scanner = MagicMock()
        scanner.scan.return_value = disc
        mock_nmap.return_value = scanner
        with pytest.raises(PortScanIncompleteError):
            scan_ports("t", "1-1000")