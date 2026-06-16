"""
service_probe.py
----------------
Actively probes HTTP/HTTPS services found by port_scanner.py to extract
deeper information about the technology stack. While port_scanner.py
finds what ports are open, this module figures out exactly what is
running behind them at the application layer.
 
Only runs against ports where port_scanner identified an HTTP-based service.
 
CONTAINS:
  - probe_http(host: str, port: int, use_tls: bool) -> HttpFinding
  - grab_tls_info(host: str, port: int) -> CertInfo
  - check_security_headers(headers: dict) -> list[str]
  - probe_all_http_ports(host: str, ports: list[PortResult]) -> list[HttpFinding]
 
IMPORTANT:
  - Set a 10 second timeout on all HTTP requests — do not let one
    slow service hold up the entire scan.
  - Send a realistic User-Agent header to avoid being blocked.
  - Follow up to 3 redirects but log each redirect in the findings.
  - Do not send any credentials or attempt any authentication.
    This module is passive observation only.
 
EXAMPLE USAGE:
  from scanner_core.service_probe import probe_all_http_ports
  from scanner_core.port_scanner import scan_ports
 
  ports = scan_ports("example.com", "80,443,8080,8443")
  findings = probe_all_http_ports("example.com", ports)
"""

import httpx
import logging
import socket
import ssl
import urllib3
import warnings
from datetime import datetime, timezone
from typing import Iterable

from .models import CertInfo, Finding, HttpFinding, PortResult

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 10
HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000]
TLS_PORTS = [443, 8443]
WEAK_TLS_VERSIONS = [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
USER_AGENT = "Mozilla/5.0 (compatible; EASM-Scanner/1.0)"

warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)


def _extract_cert_name(entries: list[tuple[str, str]] | None) -> str | None:
    """Extract the first matching name entry from a certificate section."""
    if not entries:
        return None
    for key, value in entries:
        if key.lower() in ("commonname", "common_name", "cn"):
            return value
    return entries[0][1]


def _parse_cert_time(value: str) -> str | None:
    """Convert certificate time strings to ISO 8601."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc).isoformat()
        except (ValueError, TypeError):
            continue
    return None


def _detect_cms(text: str) -> str | None:
    """Detect common CMS platforms from the page body."""
    lower = text.lower()
    if "/wp-content/" in lower or "/wp-includes/" in lower:
        return "WordPress"
    if "drupal.settings" in lower or "/sites/default/" in lower:
        return "Drupal"
    if "/components/com_" in lower:
        return "Joomla"
    return None


def check_security_headers(headers: dict[str, str]) -> list[str]:
    """Return a list of missing security header names."""
    lowered = {key.lower(): value for key, value in headers.items()}
    missing = [header for header in SECURITY_HEADERS if lowered.get(header.lower()) in (None, "")]
    return missing


def grab_tls_info(host: str, port: int) -> CertInfo:
    """Open a TLS connection to the host and extract certificate details."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    address = (host, port)
    cert_info = CertInfo(
        domain=host,
        issuer=None,
        valid_from=None,
        valid_to=None,
        days_until_expiry=None,
        is_expired=False,
        tls_version=None,
        subject_alt_names=[],
    )

    try:
        with socket.create_connection(address, timeout=HTTP_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as conn:
                cert = conn.getpeercert()
                cert_info.tls_version = conn.version()
                subject = cert.get("subject")
                cert_info.domain = _extract_cert_name(subject[0]) if isinstance(subject, (list, tuple)) and subject else host
                issuer = cert.get("issuer")
                cert_info.issuer = _extract_cert_name(issuer[0]) if isinstance(issuer, (list, tuple)) and issuer else None
                san = cert.get("subjectAltName", [])
                cert_info.subject_alt_names = [value for typ, value in san if typ.lower() == "dns"]
                valid_from = cert.get("notBefore")
                valid_to = cert.get("notAfter")
                cert_info.valid_from = _parse_cert_time(valid_from) if isinstance(valid_from, str) else None
                cert_info.valid_to = _parse_cert_time(valid_to) if isinstance(valid_to, str) else None
                if cert_info.valid_to:
                    expiry = datetime.fromisoformat(cert_info.valid_to)
                    now = datetime.now(timezone.utc)
                    cert_info.days_until_expiry = int((expiry - now).total_seconds() / 86400)
                    cert_info.is_expired = expiry < now
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        logger.warning("service_probe: TLS grab failed for %s:%s: %s", host, port, exc)

    return cert_info


def probe_http(host: str, port: int, use_tls: bool = False) -> HttpFinding:
    """Make a GET request to an HTTP/HTTPS service and return an HttpFinding."""
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}"
    headers = {"User-Agent": USER_AGENT}
    finding = HttpFinding(url=url)

    try:
        response = httpx.get(
            url,
            headers=headers,
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
            verify=False,
        )
        finding.status_code = response.status_code
        finding.server_header = response.headers.get("Server")
        finding.powered_by = response.headers.get("X-Powered-By")
        finding.missing_headers = check_security_headers(dict(response.headers))
        finding.cms_detected = _detect_cms(response.text)
        if use_tls:
            finding.cert = grab_tls_info(host, port)
    except (httpx.RequestError, ssl.SSLError, socket.timeout, OSError) as exc:
        logger.warning("service_probe: HTTP probe failed for %s: %s", url, exc)
    return finding


def _supports_tls_version(host: str, port: int, version: ssl.TLSVersion) -> bool:
    """Return True if the server completes a handshake at exactly *version*."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
    except (ValueError, OSError):
        return False  # protocol disabled in this Python/OpenSSL build
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def audit_tls(host: str, port: int) -> list[Finding]:
    """Detect weak TLS protocols and certificate validation problems on a port."""
    findings: list[Finding] = []

    for name, version in WEAK_TLS_VERSIONS:
        if _supports_tls_version(host, port, version):
            findings.append(Finding(
                title=f"Deprecated {name} enabled",
                severity="MEDIUM",
                category="tls",
                description=f"The server at {host}:{port} negotiates the deprecated {name} protocol.",
                target=f"{host}:{port}",
                remediation="Disable TLS 1.0/1.1; require TLS 1.2+.",
                source="service_probe",
            ))

    # Strict, verifying handshake to surface cert problems.
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError as exc:
        reason = str(exc).lower()
        if "self-signed" in reason or "self signed" in reason:
            findings.append(Finding(title="Self-signed TLS certificate", severity="MEDIUM", category="tls",
                                    description=f"{host}:{port} presents a self-signed certificate.",
                                    target=f"{host}:{port}", remediation="Use a certificate from a trusted CA.", source="service_probe"))
        elif "expired" in reason:
            findings.append(Finding(title="Expired TLS certificate", severity="HIGH", category="tls",
                                    description=f"{host}:{port} presents an expired certificate.",
                                    target=f"{host}:{port}", remediation="Renew the TLS certificate.", source="service_probe"))
        elif "match" in reason:
            findings.append(Finding(title="TLS certificate hostname mismatch", severity="MEDIUM", category="tls",
                                    description=f"The certificate at {host}:{port} does not match the hostname.",
                                    target=f"{host}:{port}", remediation="Issue a certificate covering this hostname (SAN).", source="service_probe"))
        else:
            findings.append(Finding(title="TLS certificate validation failed", severity="LOW", category="tls",
                                    description=str(exc), target=f"{host}:{port}", source="service_probe"))
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        logger.debug("service_probe: TLS audit connect failed for %s:%s: %s", host, port, exc)

    return findings


def audit_all_tls(host: str, ports: Iterable[PortResult]) -> list[Finding]:
    """Run TLS audits against all TLS-bearing ports discovered on the host."""
    findings: list[Finding] = []
    seen: set[int] = set()
    for port in ports or []:
        service = (port.service or "").lower()
        use_tls = port.port in TLS_PORTS or "ssl" in service or "https" in service
        if not use_tls or port.port in seen:
            continue
        seen.add(port.port)
        findings.extend(audit_tls(host, port.port))
    logger.info("service_probe: %d TLS findings for %s", len(findings), host)
    return findings


def probe_all_http_ports(host: str, ports: Iterable[PortResult]) -> list[HttpFinding]:
    """Probe all HTTP/HTTPS relevant ports and return HttpFinding objects."""
    findings: list[HttpFinding] = []
    for port in ports:
        service = (port.service or "").lower()
        should_probe = service in {"http", "https", "http-alt", "ssl"} or port.port in HTTP_PORTS
        if not should_probe:
            continue

        use_tls = port.port in (443, 8443) or "ssl" in service or "https" in service
        findings.append(probe_http(host, port.port, use_tls=use_tls))

    return findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    demo_host = "example.com"
    finding = probe_http(demo_host, 80, use_tls=False)
    print(finding.model_dump_json(indent=2))
    print("Missing headers:", finding.missing_headers)
