"""
dns_enum.py
-----------
Enumerates DNS records for a target domain and attempts to discover
subdomains through wordlist brute-forcing. Subdomains are a major
part of the external attack surface — dev, staging, admin, and api
subdomains are frequently forgotten and left exposed.
 
CONTAINS:
  - get_dns_records(domain: str) -> list[DNSRecord]
 
    Queries standard DNS record types for the domain using dnspython.
 
    Record types to fetch:
      - A     : IPv4 address(es) the domain resolves to
      - AAAA  : IPv6 address(es)
      - MX    : mail servers (misconfigured MX can enable email spoofing)
      - TXT   : text records — often contain SPF, DKIM, verification tokens
      - NS    : authoritative name servers
      - CNAME : canonical name aliases
 
    Returns list[DNSRecord], one per record found.
 
  - enumerate_subdomains(domain: str) -> list[SubdomainResult]
 
    Brute-forces subdomains by prepending words from a built-in wordlist
    and checking if they resolve to an IP address.
 
    Wordlist should cover at minimum:
      www, mail, remote, blog, webmail, server, ns1, ns2, smtp, api,
      dev, staging, test, portal, admin, vpn, ftp, m, app, dashboard
 
    For each subdomain that resolves:
      - Record the subdomain name
      - Record the resolved IP address
      - Check if the IP is different from the main domain (interesting if so)
 
    Returns list[SubdomainResult]
 
  - check_zone_transfer(domain: str) -> bool | list[str]
 
    Attempts a DNS zone transfer (AXFR) against each name server.
    A successful zone transfer is a HIGH severity finding because it
    reveals the entire internal DNS structure of the organisation.
 
    Returns:
      - False if all name servers correctly reject the transfer
      - list of exposed records if any name server allows it
 
  - run_dns_enum(domain: str) -> dict
 
    Convenience wrapper that runs all three functions above and
    returns a combined dict. This is what scan_worker.py calls.
 
IMPORTANT:
  - Use asyncio for subdomain brute-forcing — checking 50+ subdomains
    sequentially is too slow. Resolve them concurrently with a semaphore
    to limit to 20 concurrent DNS queries at a time.
  - Zone transfer attempts are legitimate recon but log them clearly.
  - Do not use external subdomain APIs here (that lives in osint_fetcher.py).
    This module only does direct DNS queries.
 
EXAMPLE USAGE:
  from scanner_core.dns_enum import run_dns_enum
  results = run_dns_enum("example.com")
  print(results["subdomains"])
  print(results["zone_transfer_vulnerable"])
"""

import asyncio
import logging
import socket
from typing import Any

import dns.exception
import dns.query
import dns.resolver
import dns.zone

try:
    from .models import DNSRecord, SubdomainResult
except ImportError:
    from models import DNSRecord, SubdomainResult

logger = logging.getLogger(__name__)

DEFAULT_WORDLIST = [
    "www",
    "mail",
    "remote",
    "blog",
    "webmail",
    "server",
    "ns1",
    "ns2",
    "smtp",
    "api",
    "dev",
    "staging",
    "test",
    "portal",
    "admin",
    "vpn",
    "ftp",
    "m",
    "app",
    "dashboard",
]
MAX_CONCURRENT_QUERIES = 20
DNS_TIMEOUT_SECONDS = 5


def _normalize_domain(target: str) -> str:
    """Normalize a target string into a bare domain name."""
    host = target.strip()
    if host.startswith("http://") or host.startswith("https://"):
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0].lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _resolve_host(domain: str, record_type: str) -> list[str]:
    """Resolve a DNS record type for a domain and return string values."""
    try:
        answer = dns.resolver.resolve(domain, record_type)
        return [str(item).strip() for item in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
        logger.debug("dns_enum: no %s answer for %s: %s", record_type, domain, exc)
    except Exception as exc:
        logger.warning("dns_enum: DNS resolution failed for %s %s: %s", domain, record_type, exc)
    return []


def get_dns_records(domain: str) -> list[DNSRecord]:
    """Fetch standard DNS records for a domain and return DNSRecord objects."""
    name = _normalize_domain(domain)
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
    records: list[DNSRecord] = []

    for record_type in record_types:
        values = _resolve_host(name, record_type)
        for value in values:
            if record_type == "TXT":
                value = value.strip('"')
            records.append(DNSRecord(record_type=record_type, name=name, value=value, ttl=None))

    logger.info("dns_enum: found %d DNS records for %s", len(records), name)
    return records


def _is_different_ip(main_ip: str | None, resolved_ip: str) -> bool:
    """Return True if the resolved subdomain IP differs from the main domain IP."""
    return bool(main_ip and resolved_ip != main_ip)


def _build_subdomain_result(subdomain: str, ips: list[str], main_ip: str | None) -> SubdomainResult:
    """Create a SubdomainResult from a resolved IP record."""
    return SubdomainResult(
        subdomain=subdomain,
        ip_address=ips[0] if ips else None,
        is_different_ip=_is_different_ip(main_ip, ips[0]) if ips else False,
    )


def enumerate_subdomains(domain: str) -> list[SubdomainResult]:
    """Brute-force a list of common subdomains and return resolved results."""
    root_domain = _normalize_domain(domain)
    main_ips = _resolve_host(root_domain, "A")
    main_ip = main_ips[0] if main_ips else None
    candidates = [f"{word}.{root_domain}" for word in DEFAULT_WORDLIST]
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)

    async def _worker(name: str) -> SubdomainResult | None:
        async with semaphore:
            try:
                answer = await asyncio.to_thread(
                    dns.resolver.resolve,
                    name,
                    "A",
                )
                ips = [str(item).strip() for item in answer]
                if ips:
                    return _build_subdomain_result(name, ips, main_ip)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                return None
            except Exception as exc:
                logger.debug("dns_enum: subdomain resolution error for %s: %s", name, exc)
                return None

    async def _runner() -> list[SubdomainResult]:
        raw_results = await asyncio.gather(*[_worker(name) for name in candidates])
        return [result for result in raw_results if result]

    try:
        results = asyncio.run(_runner())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(_runner())
        loop.close()

    logger.info("dns_enum: discovered %d subdomains for %s", len(results), root_domain)
    return results


def _get_name_servers(domain: str) -> list[str]:
    """Return authoritative name servers for a domain."""
    return [ns.rstrip('.') for ns in _resolve_host(domain, "NS")]


def _attempt_zone_transfer(ns: str, domain: str) -> list[str] | None:
    """Attempt a DNS zone transfer against a single authoritative NS."""
    try:
        ns_ip = socket.gethostbyname(ns)
        transfer = dns.query.xfr(ns_ip, domain, lifetime=DNS_TIMEOUT_SECONDS)
        zone = dns.zone.from_xfr(transfer)
        if not zone:
            return None
        records: list[str] = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(f"{name}.{domain} {rdataset.ttl} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
        return records if records else None
    except Exception as exc:
        logger.debug("dns_enum: zone transfer failed for %s on %s: %s", ns, domain, exc)
        return None


def check_zone_transfer(domain: str) -> bool | list[str]:
    """Attempt zone transfers against all authoritative name servers."""
    root_domain = _normalize_domain(domain)
    name_servers = _get_name_servers(root_domain)
    if not name_servers:
        logger.info("dns_enum: no NS records found for %s", root_domain)
        return False

    exposed_records: list[str] = []
    for ns in name_servers:
        records = _attempt_zone_transfer(ns, root_domain)
        if records:
            exposed_records.extend(records)
            logger.warning("dns_enum: zone transfer succeeded on %s for %s", ns, root_domain)

    if exposed_records:
        return exposed_records

    logger.info("dns_enum: no zone transfer exposure found for %s", root_domain)
    return False


def run_dns_enum(domain: str) -> dict[str, Any]:
    """Run DNS record collection, subdomain discovery, and zone transfer checks."""
    root_domain = _normalize_domain(domain)
    zone_transfer_result = check_zone_transfer(root_domain)
    return {
        "dns_records": get_dns_records(root_domain),
        "subdomains": enumerate_subdomains(root_domain),
        "zone_transfer_vulnerable": bool(zone_transfer_result),
        "zone_transfer_records": zone_transfer_result if zone_transfer_result else [],
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    demo_domain = "scanme.nmap.org"
    logger.info("dns_enum: running standalone DNS enumeration for %s", demo_domain)
    results = run_dns_enum(demo_domain)
    print("DNS records:", len(results["dns_records"]))
    print("Subdomains:", [sub.subdomain for sub in results["subdomains"]])
    print("Zone transfer:", results["zone_transfer_vulnerable"])
