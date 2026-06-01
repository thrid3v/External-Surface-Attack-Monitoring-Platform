"""
osint_fetcher.py
----------------
Fetches publicly available information about a target from three
passive sources: WHOIS, Shodan, and certificate transparency logs (crt.sh).
No active probing happens here — all data is pulled from third-party
databases that already scanned the internet independently.
 
CONTAINS:
  - fetch_whois(target: str) -> WHOISInfo
 
    Queries WHOIS for domain registration information.
 
    Returns WHOISInfo containing:
      - registrar       who the domain is registered with
      - registrant_org  organisation that owns the domain
      - created_date    when the domain was first registered
      - expiry_date     when registration expires (expired = takeover risk)
      - name_servers    list of authoritative DNS servers
      - country         registrant country code
 
  - fetch_shodan(target: str) -> dict
 
    Queries the Shodan API for what Shodan already knows about this IP.
    Requires SHODAN_API_KEY in .env — if not set, skip and return empty dict.
 
    Returns a dict containing:
      - open_ports      list of ports Shodan has seen open
      - hostnames       reverse DNS hostnames Shodan found
      - org             organisation that owns the IP (from BGP data)
      - isp             internet service provider
      - country         country the IP is located in
      - last_update     when Shodan last scanned this IP
      - vulns           list of CVE IDs Shodan flagged (if any)
      - tags            Shodan tags e.g. ["cloud", "self-signed"]
 
  - fetch_certificates(target: str) -> list[CertInfo]
 
    Queries crt.sh (certificate transparency logs) to find all TLS
    certificates ever issued for this domain and its subdomains.
    This is one of the best free ways to discover subdomains.
 
    Returns list[CertInfo] containing:
      - domain          the domain name on the cert
      - issuer          who issued the cert (Let's Encrypt, DigiCert etc.)
      - valid_from      cert validity start date
      - valid_to        cert expiry date
      - expired         bool — True if valid_to is in the past
 
  - fetch_all(target: str) -> OSINTResult
 
    Convenience function that calls all three sources above and
    returns a single OSINTResult object. This is what scan_worker.py calls.
 
IMPORTANT:
  - All three functions should handle failures independently.
    If Shodan is down or the API key is missing, still return WHOIS and certs.
  - crt.sh is a public API with no auth required — use it freely.
    Endpoint: https://crt.sh/?q={domain}&output=json
  - Log warnings for any source that fails, do not raise exceptions.
 
EXAMPLE USAGE:
  from scanner_core.osint_fetcher import fetch_all
  result = fetch_all("example.com")
  print(result.whois.registrar)
  print(result.certificates)
"""
import ipaddress
import logging
import os
import re
import socket
from datetime import datetime
from typing import Any

import requests
from dotenv import load_dotenv

try:
    import shodan
except ImportError:  # pragma: no cover
    shodan = None

try:
    import whois as whois_lib
    if hasattr(whois_lib, "query") and not hasattr(whois_lib, "whois"):
        setattr(whois_lib, "whois", whois_lib.query)
except ImportError:  # pragma: no cover
    whois_lib = None

try:
    from .models import CertInfo, OSINTResult, WHOISInfo
except ImportError:
    from models import CertInfo, OSINTResult, WHOISInfo

logger = logging.getLogger(__name__)

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
CRT_SH_URL = "https://crt.sh/"
REQUEST_TIMEOUT_SECONDS = 10


def _is_ip_address(value: str) -> bool:
    """Return True if the value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_base_domain(target: str) -> str:
    """Extract the base domain from a URL or hostname."""
    if target.startswith("http://") or target.startswith("https://"):
        target = target.split("://", 1)[1]
    target = target.split("/")[0].lower()
    if target.startswith("www."):
        target = target[4:]
    return target


def _normalize_name_values(name_value: str) -> list[str]:
    """Split crt.sh name_value field into unique hostnames."""
    if not isinstance(name_value, str):
        return []
    hosts = [host.strip().lower() for host in re.split(r"[\n,]+", name_value) if host.strip()]
    return sorted(set(hosts))


def _parse_datetime(value: Any) -> str | None:
    """Convert common WHOIS/crt.sh date values into ISO 8601 strings."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        for item in value:
            parsed = _parse_datetime(item)
            if parsed:
                return parsed
        return None
    if isinstance(value, str):
        trimmed = value.strip()
        try:
            return datetime.fromisoformat(trimmed).isoformat()
        except ValueError:
            pass
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%d %b %Y", "%Y.%m.%d", "%m/%d/%Y"):
            try:
                return datetime.strptime(trimmed, fmt).isoformat()
            except ValueError:
                continue
    return None


def _format_whois_record(record: dict[str, Any]) -> WHOISInfo:
    """Convert raw whois data into a WHOISInfo object."""
    return WHOISInfo(
        registrar=record.get("registrar") or record.get("registrar_name"),
        registrant_org=record.get("org") or record.get("registrant_organization") or record.get("registrant_org"),
        created_date=_parse_datetime(record.get("creation_date") or record.get("created_date")),
        expiry_date=_parse_datetime(record.get("expiration_date") or record.get("expiry_date") or record.get("updated_date")),
        is_expired=bool(record.get("status") == "expired"),
        name_servers=[ns.strip().lower() for ns in (record.get("name_servers") or []) if isinstance(ns, str) and ns.strip()],
        country=record.get("country") or record.get("registrant_country"),
    )


def fetch_whois(target: str) -> WHOISInfo:
    """Query WHOIS for target registration and ownership data."""
    if whois_lib is None:
        logger.warning("osint_fetcher: python-whois package is not installed")
        return None

    domain = _extract_base_domain(target)
    if _is_ip_address(domain):
        logger.warning("osint_fetcher: WHOIS lookup skipped for IP address %s", target)
        return WHOISInfo()

    try:
        if hasattr(whois_lib, "whois"):
            raw = whois_lib.whois(domain)
        elif hasattr(whois_lib, "query"):
            raw = whois_lib.query(domain)
        else:
            raise AttributeError("whois module has no query or whois callable")
        if not isinstance(raw, dict):
            raw = raw.__dict__ if hasattr(raw, "__dict__") else {}
        return _format_whois_record(raw)
    except Exception as exc:
        logger.warning("osint_fetcher: WHOIS lookup failed for %s: %s", domain, exc)
        return None


def _resolve_to_ip(target: str) -> str | None:
    """Resolve a hostname to an IP address if needed."""
    if _is_ip_address(target):
        return target
    try:
        return socket.gethostbyname(_extract_base_domain(target))
    except socket.gaierror as exc:
        logger.warning("osint_fetcher: DNS resolution failed for %s: %s", target, exc)
        return None


def fetch_shodan(target: str) -> dict[str, Any]:
    """Query Shodan for metadata about the target IP address."""
    if shodan is None:
        logger.warning("osint_fetcher: shodan package is not installed")
        return {
            "open_ports": [],
            "hostnames": [],
            "org": None,
            "isp": None,
            "country": None,
            "last_update": None,
            "vulns": [],
            "tags": [],
        }
    if not SHODAN_API_KEY:
        logger.warning("osint_fetcher: SHODAN_API_KEY not configured")
        return {
            "open_ports": [],
            "hostnames": [],
            "org": None,
            "isp": None,
            "country": None,
            "last_update": None,
            "vulns": [],
            "tags": [],
        }

    ip_address = _resolve_to_ip(target)
    if ip_address is None:
        return {
            "open_ports": [],
            "hostnames": [],
            "org": None,
            "isp": None,
            "country": None,
            "last_update": None,
            "vulns": [],
            "tags": [],
        }

    client = shodan.Shodan(SHODAN_API_KEY)
    try:
        host = client.host(ip_address)
    except Exception as exc:
        logger.warning("osint_fetcher: Shodan query failed for %s (%s): %s", target, ip_address, exc)
        return {
            "open_ports": [],
            "hostnames": [],
            "org": None,
            "isp": None,
            "country": None,
            "last_update": None,
            "vulns": [],
            "tags": [],
        }

    return {
        "open_ports": sorted(host.get("ports", [])) if isinstance(host.get("ports"), list) else [],
        "hostnames": sorted(host.get("hostnames", [])) if isinstance(host.get("hostnames"), list) else [],
        "org": host.get("org"),
        "isp": host.get("isp"),
        "country": host.get("country_name") or host.get("country_code"),
        "last_update": host.get("last_update"),
        "vulns": sorted(host.get("vulns", [])) if isinstance(host.get("vulns"), list) else [],
        "tags": sorted(host.get("tags", [])) if isinstance(host.get("tags"), list) else [],
    }


def _build_crtsh_query(domain: str) -> str:
    """Build a crt.sh wildcard query for a given domain."""
    domain = _extract_base_domain(domain)
    return f"%.{domain}"


def _parse_certificate(item: dict[str, Any], domain: str) -> list[CertInfo]:
    """Convert one crt.sh JSON item into one or more CertInfo entries."""
    if not isinstance(item, dict):
        return []

    issuer = item.get("issuer_name") or item.get("issuer")
    valid_from = _parse_datetime(item.get("not_before") or item.get("notBefore"))
    valid_to = _parse_datetime(item.get("not_after") or item.get("notAfter"))
    names = _normalize_name_values(item.get("name_value") or item.get("common_name") or domain)

    results: list[CertInfo] = []
    for name in names:
        results.append(
            CertInfo(
                domain=name,
                issuer=issuer,
                valid_from=valid_from,
                valid_to=valid_to,
                days_until_expiry=None,
                is_expired=False,
                tls_version=None,
                subject_alt_names=names,
            )
        )
    return results


def _compute_certificate_liveness(cert: CertInfo) -> CertInfo:
    """Add expiry data to a CertInfo object."""
    if cert.valid_to:
        try:
            expiry = datetime.fromisoformat(cert.valid_to)
            cert.days_until_expiry = int((expiry - datetime.utcnow()).total_seconds() / 86400)
            cert.is_expired = expiry < datetime.utcnow()
        except ValueError:
            cert.days_until_expiry = None
    return cert


def fetch_certificates(target: str) -> list[CertInfo]:
    """Query crt.sh and return certificate data for the target domain."""
    domain = _extract_base_domain(target)
    if _is_ip_address(domain):
        logger.warning("osint_fetcher: crt.sh lookup skipped for IP address %s", target)
        return []

    query = _build_crtsh_query(domain)
    params = {"q": query, "output": "json"}
    try:
        response = requests.get(CRT_SH_URL, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
    except Exception as exc:
        logger.warning("osint_fetcher: crt.sh query failed for %s: %s", domain, exc)
        return []

    if response.status_code != 200:
        logger.warning("osint_fetcher: crt.sh returned status %s for %s", response.status_code, domain)
        return []

    try:
        certificates = response.json()
    except ValueError as exc:
        logger.warning("osint_fetcher: crt.sh returned invalid JSON for %s: %s", domain, exc)
        return []

    parsed: list[CertInfo] = []
    seen_domains: set[str] = set()
    for item in certificates:
        for cert in _parse_certificate(item, domain):
            cert = _compute_certificate_liveness(cert)
            if cert.domain not in seen_domains:
                parsed.append(cert)
                seen_domains.add(cert.domain)

    logger.info("osint_fetcher: found %d certificates for %s", len(parsed), domain)
    return parsed


def fetch_all(target: str) -> OSINTResult:
    """Run WHOIS, Shodan, and crt.sh fetchers and aggregate results."""
    whois_data = fetch_whois(target)
    shodan_data = fetch_shodan(target)
    certs = fetch_certificates(target)
    subdomains = sorted({cert.domain for cert in certs if cert.domain and cert.domain != _extract_base_domain(target)})

    return OSINTResult(
        whois=whois_data,
        shodan_ports=shodan_data.get("open_ports", []),
        shodan_vulns=shodan_data.get("vulns", []),
        shodan_org=shodan_data.get("org"),
        shodan_country=shodan_data.get("country"),
        certificates=certs,
        subdomains_from_certs=subdomains,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    demo_target = "scanme.nmap.org"
    logger.info("osint_fetcher: running standalone OSINT fetch for %s", demo_target)
    result = fetch_all(demo_target)
    print("WHOIS registrar:", result.whois.registrar)
    print("Shodan ports:", result.shodan_ports)
    print("Certificates found:", len(result.certificates)) 