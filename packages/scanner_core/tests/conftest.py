import pytest
from scanner_core.models import (
    PortResult, CVEResult, OSINTResult,
    WHOISInfo, HttpFinding, DNSRecord, SubdomainResult
)

@pytest.fixture
def mock_port_open():
    return PortResult(
        port=80, protocol="tcp", state="open",
        service="http", product="Apache httpd", version="2.4.51"
    )

@pytest.fixture
def mock_port_ssh():
    return PortResult(
        port=22, protocol="tcp", state="open",
        service="ssh", product="OpenSSH", version="6.6.1"
    )

@pytest.fixture
def mock_cve_critical():
    return CVEResult(
        cve_id="CVE-2021-41773",
        description="Path traversal in Apache 2.4.49",
        cvss_score=9.8,
        cvss_version="3.1",
        severity="CRITICAL",
        published_date="2021-10-05"
    )

@pytest.fixture
def mock_cve_medium():
    return CVEResult(
        cve_id="CVE-2016-0777",
        description="OpenSSH roaming buffer overflow",
        cvss_score=4.0,
        cvss_version="3.1",
        severity="MEDIUM",
        published_date="2016-01-14"
    )

@pytest.fixture
def mock_osint():
    return OSINTResult(
        whois=WHOISInfo(
            registrar="GoDaddy",
            registrant_org="Example Corp",
            created_date="2000-01-01",
            expiry_date="2030-01-01",
            name_servers=["ns1.example.com"]
        ),
        shodan_ports=[80, 443],
        shodan_org="Example ISP"
    )

@pytest.fixture
def mock_http_finding():
    return HttpFinding(
        url="http://example.com",
        status_code=200,
        server_header="Apache/2.4.51",
        missing_headers=["Content-Security-Policy", "X-Frame-Options"]
    )