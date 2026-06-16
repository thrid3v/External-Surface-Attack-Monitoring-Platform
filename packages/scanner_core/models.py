"""
models.py
---------
Single source of truth for all data shapes used across scanner_core.
Every other module imports from here and returns these Pydantic models.
Nothing in this file does any scanning — it only defines structure.
 
CONTAINS:
  - PortResult         : one open port found on the target
  - CVEResult          : a single CVE matched against a service version
  - DNSRecord          : one DNS record (A, MX, TXT, NS, CNAME)
  - SubdomainResult    : a discovered subdomain with its resolved IP
  - CertInfo           : TLS certificate details pulled from the target
  - WHOISInfo          : registration and ownership data for the domain
  - OSINTResult        : aggregated output from all OSINT sources (WHOIS, Shodan, crt.sh)
  - HttpFinding        : HTTP / TLS findings for a URL
  - ScanStatus         : enum — PENDING | RUNNING | COMPLETE | FAILED
  - ScanReport         : the final top-level object that wraps everything above.
                         This is what gets saved to the database and returned by the API.
 
RULES:
  - All fields should have a default value or be Optional so partial
    results can be stored if a module fails mid-scan.
  - Use enums for any field with a fixed set of values (severity, status).
  - Keep field names snake_case and self-explanatory.
  - Add a Field(..., description="...") on every field — this doubles as
    documentation and powers the MCP tool schemas automatically.
 
EXAMPLE USAGE:
  from scanner_core.models import ScanReport, PortResult
"""

import logging
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class CVEResult(BaseModel):
    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2021-41773")
    description: str = Field(..., description="Short description of the vulnerability")
    cvss_score: Optional[float] = Field(None, description="CVSS score from 0.0 to 10.0")
    cvss_version: Optional[str] = Field(None, description="CVSS version, e.g. 3.1 or 2.0")
    severity: str = Field(..., description="Severity label: CRITICAL|HIGH|MEDIUM|LOW|NONE")
    published_date: Optional[str] = Field(None, description="Vulnerability publication date")
    references: list[str] = Field(default_factory=list, description="URLs or references for the CVE")


class PortResult(BaseModel):
    port: int = Field(..., description="Port number discovered on the target")
    protocol: str = Field(..., description='Protocol type, e.g. "tcp" or "udp"')
    state: str = Field(..., description='Port state, e.g. "open", "filtered", or "closed"')
    service: Optional[str] = Field(None, description="Service name detected on the port")
    product: Optional[str] = Field(None, description="Product name reported by the service")
    version: Optional[str] = Field(None, description="Service version string if available")
    banner: Optional[str] = Field(None, description="Raw banner data captured from the service")
    cves: list[CVEResult] = Field(default_factory=list, description="List of CVEs associated with this port")


class DNSRecord(BaseModel):
    record_type: str = Field(..., description="DNS record type, e.g. A, MX, TXT, NS, CNAME, AAAA")
    name: str = Field(..., description="DNS record name")
    value: str = Field(..., description="DNS record value")
    ttl: Optional[int] = Field(None, description="Time to live for the record in seconds")


class SubdomainResult(BaseModel):
    subdomain: str = Field(..., description="Discovered subdomain, e.g. dev.example.com")
    ip_address: Optional[str] = Field(None, description="Resolved IP address for the subdomain")
    is_different_ip: bool = Field(False, description="True if subdomain IP differs from the main domain")
    source: str = Field("dns_bruteforce", description="How the subdomain was discovered: dns_bruteforce | cert_transparency")


class CertInfo(BaseModel):
    domain: str = Field(..., description="Domain name for the certificate")
    issuer: Optional[str] = Field(None, description="Certificate issuer")
    valid_from: Optional[str] = Field(None, description="Certificate validity start date")
    valid_to: Optional[str] = Field(None, description="Certificate expiry date")
    days_until_expiry: Optional[int] = Field(None, description="Days until the certificate expires")
    is_expired: bool = Field(False, description="True when the certificate is expired")
    tls_version: Optional[str] = Field(None, description="TLS version used by the certificate")
    subject_alt_names: list[str] = Field(default_factory=list, description="Subject Alternative Names listed on the certificate")


class WHOISInfo(BaseModel):
    registrar: Optional[str] = Field(None, description="Domain registrar name")
    registrant_org: Optional[str] = Field(None, description="Registrant organization")
    created_date: Optional[str] = Field(None, description="Domain creation date")
    expiry_date: Optional[str] = Field(None, description="Domain expiry date")
    is_expired: bool = Field(False, description="True if the WHOIS registration is expired")
    name_servers: list[str] = Field(default_factory=list, description="List of configured name servers")
    country: Optional[str] = Field(None, description="Registrant country")


class OSINTResult(BaseModel):
    whois: Optional[WHOISInfo] = Field(None, description="WHOIS lookup results")
    shodan_ports: list[int] = Field(default_factory=list, description="Open ports reported by Shodan")
    shodan_vulns: list[str] = Field(default_factory=list, description="Vulnerabilities reported by Shodan")
    shodan_org: Optional[str] = Field(None, description="Organization name reported by Shodan")
    shodan_country: Optional[str] = Field(None, description="Country reported by Shodan")
    certificates: list[CertInfo] = Field(default_factory=list, description="Certificates discovered from public sources")
    subdomains_from_certs: list[str] = Field(default_factory=list, description="Subdomains extracted from certificate SANs")


class HttpFinding(BaseModel):
    url: str = Field(..., description="URL probed for HTTP/TLS findings")
    status_code: Optional[int] = Field(None, description="HTTP status code returned by the target")
    server_header: Optional[str] = Field(None, description="Value of the Server response header")
    powered_by: Optional[str] = Field(None, description="Value of the X-Powered-By header or equivalent")
    cms_detected: Optional[str] = Field(None, description="Detected CMS, e.g. WordPress 6.1")
    missing_headers: list[str] = Field(default_factory=list, description="Security headers missing from the response")
    cert: Optional[CertInfo] = Field(None, description="TLS certificate details for the endpoint")


class Finding(BaseModel):
    """A generic security finding that is not a versioned CVE — misconfigurations,
    exposures, takeovers, weak TLS, template (nuclei) hits, etc."""

    title: str = Field(..., description="Short finding title")
    severity: str = Field(..., description="Severity label: CRITICAL|HIGH|MEDIUM|LOW|INFO")
    category: str = Field(..., description="Finding category, e.g. web_exposure|tls|takeover|email|nuclei")
    description: str = Field("", description="What the finding is and why it matters")
    target: Optional[str] = Field(None, description="Affected URL, host, or subdomain")
    evidence: Optional[str] = Field(None, description="Evidence supporting the finding")
    remediation: Optional[str] = Field(None, description="Suggested remediation")
    source: str = Field("", description="Module that produced the finding")
    references: list[str] = Field(default_factory=list, description="Reference URLs")


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class ScanReport(BaseModel):
    scan_id: str = Field(..., description="UUID assigned at scan start")
    target: str = Field(..., description="Original scan target provided by the caller")
    status: ScanStatus = Field(..., description="Current scan status")
    risk_score: Optional[int] = Field(None, description="Aggregate risk score from 0-100")
    risk_label: Optional[str] = Field(None, description="Risk label: CRITICAL|HIGH|MEDIUM|LOW|MINIMAL")
    severity_summary: dict[str, int] = Field(default_factory=dict, description="Counts of findings by severity")
    ports: list[PortResult] = Field(default_factory=list, description="Discovered open ports and service details")
    cves: list[CVEResult] = Field(default_factory=list, description="Deduplicated CVE findings across all ports")
    dns_records: list[DNSRecord] = Field(default_factory=list, description="Collected DNS records")
    subdomains: list[SubdomainResult] = Field(default_factory=list, description="Discovered subdomains")
    zone_transfer_vulnerable: bool = Field(False, description="True if any authoritative name server allowed a DNS zone transfer (AXFR)")
    zone_transfer_records: list[str] = Field(default_factory=list, description="Records exposed via zone transfer, if vulnerable")
    osint: Optional[OSINTResult] = Field(None, description="Aggregated OSINT findings")
    http_findings: list[HttpFinding] = Field(default_factory=list, description="HTTP and TLS probe results")
    findings: list[Finding] = Field(default_factory=list, description="Non-CVE security findings (misconfig, exposure, takeover, TLS, nuclei)")
    top_findings: list[CVEResult] = Field(default_factory=list, description="Top CVE findings by score")
    started_at: Optional[str] = Field(None, description="Scan start timestamp")
    completed_at: Optional[str] = Field(None, description="Scan completion timestamp")
    scan_duration_seconds: Optional[float] = Field(None, description="Scan duration in seconds")
    modules_run: list[str] = Field(default_factory=list, description="List of scanner modules executed")
    errors: dict[str, str] = Field(default_factory=dict, description="Errors encountered by module")


if __name__ == "__main__":
    logger.info("Running models.py self-check")
    example_report = ScanReport(
        scan_id="test-scan-id",
        target="scanme.nmap.org",
        status=ScanStatus.COMPLETE,
        risk_score=42,
        risk_label="MEDIUM",
        severity_summary={"critical": 0, "high": 1, "medium": 3, "low": 4},
        ports=[
            PortResult(
                port=22,
                protocol="tcp",
                state="open",
                service="ssh",
                product="OpenSSH",
                version="7.9",
                banner="SSH-2.0-OpenSSH_7.9",
                cves=[
                    CVEResult(
                        cve_id="CVE-2016-0777",
                        description="SSH vulnerability affecting certain OpenSSH versions.",
                        cvss_score=4.0,
                        cvss_version="3.0",
                        severity="MEDIUM",
                        published_date="2016-03-15",
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2016-0777"],
                    )
                ],
            )
        ],
        dns_records=[DNSRecord(record_type="A", name="scanme.nmap.org", value="45.33.32.156", ttl=300)],
        subdomains=[SubdomainResult(subdomain="www.scanme.nmap.org", ip_address="45.33.32.156")],
        osint=OSINTResult(
            whois=WHOISInfo(registrar="Example Registrar", created_date="2010-01-01", expiry_date="2030-01-01"),
            shodan_ports=[22],
            shodan_org="Nmap",
            shodan_country="US",
            certificates=[CertInfo(domain="scanme.nmap.org", issuer="Let's Encrypt", valid_from="2024-01-01", valid_to="2025-01-01", days_until_expiry=150)],
            subdomains_from_certs=["scanme.nmap.org"],
        ),
        http_findings=[
            HttpFinding(url="https://scanme.nmap.org", status_code=200, server_header="nginx", powered_by=None, cms_detected=None)
        ],
        top_findings=[],
        started_at="2026-06-01T00:00:00Z",
        completed_at="2026-06-01T00:01:00Z",
        scan_duration_seconds=60.0,
        modules_run=["port_scanner", "cve_lookup", "dns_enum", "osint_fetcher", "service_probe"],
        errors={},
    )
    print(example_report.model_dump_json(indent=2))
