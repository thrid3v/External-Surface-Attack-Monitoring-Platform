"""
port_scanner.py
---------------
Wraps python-nmap to scan a target for open ports, running services,
and software version banners. This is always the first module called
in a scan because its output (service names + versions) feeds directly
into cve_lookup.py.
 
CONTAINS:
  - scan_ports(target: str, port_range: str) -> list[PortResult]
 
    Runs an nmap scan against the target and returns a list of PortResult
    objects, one per open port found.
 
    Arguments:
      target     : IP address or hostname e.g. "192.168.1.1" or "example.com"
      port_range : nmap-style port string e.g. "1-1000" or "22,80,443,8080"
                   default to "1-1000" if not provided
 
    Returns:
      list[PortResult] — each item contains:
        - port number
        - protocol (tcp/udp)
        - state (open/closed/filtered)
        - service name  e.g. "http", "ssh", "ftp"
        - product       e.g. "Apache httpd"
        - version       e.g. "2.4.51"
        - banner        raw banner string grabbed from the service if available
 
    How it works:
      1. Call nmap via python-nmap using the -sV flag (version detection)
      2. Parse the nmap output into PortResult objects
      3. Filter to only open ports before returning
 
IMPORTANT:
  - nmap must be installed on the system separately (not just python-nmap).
    Add a check at startup and raise a clear error if nmap binary is missing.
  - Set a timeout (default 120 seconds) so a slow host doesn't hang the worker.
  - Never run this against a target without the consent check passing first.
    The consent check lives in the API layer — this module trusts it was done.
 
TEST TARGET (legal):
  scanme.nmap.org — Nmap's official public test host. Safe to scan anytime.
 
EXAMPLE USAGE:
  from scanner_core.port_scanner import scan_ports
  results = scan_ports("scanme.nmap.org", "1-1000")
  for r in results:
      print(r.port, r.service, r.version)
"""

import logging
import shutil
from typing import Any

import nmap
from nmap import PortScannerError

try:
    from .models import PortResult
except ImportError:
    from models import PortResult

logger = logging.getLogger(__name__)

DEFAULT_PORT_RANGE = "1-1000"
SCAN_TIMEOUT_SECONDS = 120
NMAP_HOST_TIMEOUT_SECONDS = 120
NMAP_MAX_RETRIES = 2


def _is_nmap_available() -> bool:
    """Return True if the nmap binary is available on the host."""
    available = shutil.which("nmap") is not None
    if not available:
        logger.error("port_scanner: nmap binary not found in PATH")
    return available


def _format_banner(product: Any, version: Any, extrainfo: Any) -> str | None:
    """Build a simple banner string from available service fingerprint fields."""
    pieces = [str(value).strip() for value in (product, version, extrainfo) if value]
    return " ".join(pieces) if pieces else None


def _normalize_state(port_data: dict[str, Any]) -> str:
    """Extract the state string from nmap port data."""
    state = port_data.get("state")
    if isinstance(state, dict):
        return state.get("state", "unknown")
    return str(state) if state is not None else "unknown"


def _get_scan_host_result(scan_data: Any, target: str) -> Any:
    """Return the matched host scan block from nmap results or scanner object."""
    if isinstance(scan_data, dict):
        scan_hosts = scan_data.get("scan", {})
        if target in scan_hosts:
            return scan_hosts[target]
        if scan_hosts:
            return next(iter(scan_hosts.values()))
        return {}

    try:
        if target in scan_data:
            return scan_data[target]
    except Exception:
        pass

    try:
        return scan_data[target]
    except Exception:
        pass

    try:
        return scan_data.get(target, {})
    except Exception:
        pass

    return {}


def _parse_nmap_ports(scan_data: dict[str, Any], target: str) -> list[PortResult]:
    """Parse nmap scan output into a list of PortResult objects."""
    results: list[PortResult] = []
    host_result = _get_scan_host_result(scan_data, target)
    if not host_result:
        logger.warning("port_scanner: no port data found for target %s", target)
        return results

    protocols = ("tcp", "udp")
    if not isinstance(host_result, dict) and hasattr(host_result, "all_protocols"):
        try:
            protocols = host_result.all_protocols()
        except Exception:
            protocols = ("tcp", "udp")

    for protocol in protocols:
        protocol_block = {}
        if isinstance(host_result, dict):
            protocol_block = host_result.get(protocol, {})
        else:
            try:
                protocol_block = host_result[protocol]
            except Exception:
                try:
                    protocol_block = host_result.get(protocol, {})
                except Exception:
                    protocol_block = {}

        if protocol_block is None:
            continue

        port_keys = []
        try:
            port_keys = list(protocol_block.keys())
        except Exception:
            continue

        for port_key in port_keys:
            try:
                port_data = protocol_block[port_key]
            except Exception:
                continue
            try:
                port_number = int(port_key)
            except (ValueError, TypeError):
                continue

            state = _normalize_state(port_data)
            if state != "open":
                continue

            service = port_data.get("name")
            product = port_data.get("product")
            version = port_data.get("version")
            extrainfo = port_data.get("extrainfo")
            banner = _format_banner(product, version, extrainfo)

            results.append(
                PortResult(
                    port=port_number,
                    protocol=protocol,
                    state=state,
                    service=service,
                    product=product,
                    version=version,
                    banner=banner,
                )
            )

    return results


_parse_nmap_output = _parse_nmap_ports

def scan_ports(target: str, port_range: str = DEFAULT_PORT_RANGE) -> list[PortResult]:
    """Run nmap against target and return a list of open PortResult objects."""
    if not _is_nmap_available():
        return []

    try:
        scanner = nmap.PortScanner()
    except PortScannerError as e:
        logger.error("port_scanner: failed to initialize python-nmap PortScanner: %s", e)
        return []
    except Exception as e:
        logger.error("port_scanner: failed to initialize nmap PortScanner: %s", e)
        return []

    arguments = (
        f"-sV -Pn --host-timeout {NMAP_HOST_TIMEOUT_SECONDS}s "
        f"--max-retries {NMAP_MAX_RETRIES}"
    )
    logger.debug(
        "port_scanner: scanning target=%s ports=%s args=%s",
        target,
        port_range,
        arguments,
    )

    try:
        scan_data = scanner.scan(hosts=target, ports=port_range, arguments=arguments)
        if isinstance(scan_data, dict) and scan_data:
            ports = _parse_nmap_ports(scan_data, target)
        else:
            ports = _parse_nmap_ports(scanner, target)
        logger.info(
            "port_scanner: found %d open ports for %s",
            len(ports),
            target,
        )
        return ports
    except PortScannerError as e:
        logger.warning("port_scanner: nmap scan failed for %s: %s", target, e)
        return []
    except FileNotFoundError as e:
        logger.error("port_scanner: nmap binary missing during scan for %s: %s", target, e)
        return []
    except Exception as e:
        logger.error("port_scanner: unexpected error scanning %s: %s", target, e)
        return []


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    target = "scanme.nmap.org"
    logger.info("port_scanner: running standalone scan against %s", target)
    results = scan_ports(target)
    if not results:
        print("No open ports discovered or nmap scan failed.")
    else:
        for port_result in results:
            print(
                f"{port_result.port}/{port_result.protocol} "
                f"{port_result.state} "
                f"{port_result.service or 'unknown'} "
                f"{port_result.product or ''} "
                f"{port_result.version or ''}"
            )
