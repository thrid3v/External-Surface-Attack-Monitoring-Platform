"""
report_gen.py
-------------
Takes the raw outputs from all scanner_core modules and assembles them
into a single structured ScanReport object. Also calculates the overall
risk score and deduplicates any overlapping findings.
 
This is the last module called in a scan. It does no network requests —
it only processes data that was already collected.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from .models import (
    CVEResult,
    DNSRecord,
    Finding,
    HttpFinding,
    OSINTResult,
    PortResult,
    ScanReport,
    ScanStatus,
    SubdomainResult,
)

logger = logging.getLogger(__name__)
TOP_FINDINGS_LIMIT = 5
CERT_EXPIRY_WARNING_DAYS = 14


def _has_expiring_or_expired_cert(
    http_findings: Optional[list[HttpFinding]],
    osint: Optional[OSINTResult],
) -> bool:
    """Return True if any observed certificate is expired or expiring soon."""
    certs = [finding.cert for finding in (http_findings or []) if finding.cert]
    if osint and osint.certificates:
        certs.extend(osint.certificates)
    for cert in certs:
        if cert.is_expired:
            return True
        if cert.days_until_expiry is not None and cert.days_until_expiry <= CERT_EXPIRY_WARNING_DAYS:
            return True
    return False


def _collect_all_cves(ports: list[PortResult]) -> list[CVEResult]:
    """Collect and deduplicate CVEs from all port scan results."""
    best_by_id: dict[str, CVEResult] = {}
    for port in ports or []:
        for cve in port.cves or []:
            existing = best_by_id.get(cve.cve_id)
            if existing is None or (cve.cvss_score or 0.0) > (existing.cvss_score or 0.0):
                best_by_id[cve.cve_id] = cve
    results = sorted(best_by_id.values(), key=lambda c: c.cvss_score or 0.0, reverse=True)
    return results


def calculate_risk_score(
    cves: list[CVEResult],
    open_port_count: int,
    http_findings: list[HttpFinding],
    osint: Optional[OSINTResult] = None,
    zone_transfer_vulnerable: bool = False,
    findings: Optional[list[Finding]] = None,
) -> int:
    """Calculate a 0-100 risk score from CVEs, open ports, HTTP hygiene,
    additional exposure signals, and non-CVE findings."""
    if not cves:
        max_cvss = 0.0
    else:
        max_cvss = max((cve.cvss_score or 0.0) for cve in cves)
    component_1 = (max_cvss / 10.0) * 40

    critical_count = sum(1 for cve in cves if cve.severity.upper() == "CRITICAL")
    high_count = sum(1 for cve in cves if cve.severity.upper() == "HIGH")
    component_2 = min(critical_count * 10 + high_count * 5, 30)

    component_3 = min(open_port_count * 1.5, 15)

    total_missing_headers = sum(len(finding.missing_headers or []) for finding in http_findings or [])
    component_4 = min(total_missing_headers * 2, 15)

    # Additional exposure signals, capped collectively so they cannot dominate.
    exposure = 0
    if zone_transfer_vulnerable:
        exposure += 15
    if _has_expiring_or_expired_cert(http_findings, osint):
        exposure += 8
    if osint and osint.whois and osint.whois.is_expired:
        exposure += 10
    if osint and osint.shodan_vulns:
        exposure += min(len(osint.shodan_vulns) * 3, 12)
    component_5 = min(exposure, 25)

    f_crit = sum(1 for f in findings or [] if (f.severity or "").upper() == "CRITICAL")
    f_high = sum(1 for f in findings or [] if (f.severity or "").upper() == "HIGH")
    f_med = sum(1 for f in findings or [] if (f.severity or "").upper() == "MEDIUM")
    component_6 = min(f_crit * 10 + f_high * 5 + f_med * 2, 30)

    final_score = int(component_1 + component_2 + component_3 + component_4 + component_5 + component_6)
    return min(final_score, 100)


def get_risk_label(score: int) -> str:
    """Convert a numeric risk score into a risk label."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "MINIMAL"


def _build_severity_summary(
    cves: list[CVEResult],
    findings: Optional[list[Finding]] = None,
) -> dict[str, int]:
    """Count CVEs and non-CVE findings by severity into a normalized summary."""
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for cve in cves or []:
        severity = (cve.severity or "").lower()
        if severity in summary:
            summary[severity] += 1
    for finding in findings or []:
        severity = (finding.severity or "").lower()
        if severity in summary:
            summary[severity] += 1
    return summary


def _get_top_findings(cves: list[CVEResult], limit: int = TOP_FINDINGS_LIMIT) -> list[CVEResult]:
    """Return the top CVEs sorted by CVSS score descending."""
    sorted_cves = sorted(cves or [], key=lambda c: c.cvss_score or 0.0, reverse=True)
    return sorted_cves[:limit]


def _merge_subdomains(
    subdomains: list[SubdomainResult],
    osint: Optional[OSINTResult],
) -> list[SubdomainResult]:
    """Merge certificate-transparency subdomains (from crt.sh, stored on the
    OSINT result) into the unified subdomain list, deduping by name and
    preserving the brute-forced entries which carry resolved IPs."""
    merged: list[SubdomainResult] = list(subdomains or [])
    seen = {sub.subdomain.lower() for sub in merged}
    if osint and osint.subdomains_from_certs:
        for name in osint.subdomains_from_certs:
            key = (name or "").strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            merged.append(SubdomainResult(subdomain=key, source="cert_transparency"))
    return merged


def _parse_started_at(started_at: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 datetime string and return a UTC datetime."""
    if not started_at:
        return None
    try:
        parsed = datetime.fromisoformat(started_at)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def generate_report(
    scan_id: str,
    target: str,
    started_at: str,
    ports: Optional[list[PortResult]] = None,
    osint: Optional[OSINTResult] = None,
    dns_records: Optional[list[DNSRecord]] = None,
    subdomains: Optional[list[SubdomainResult]] = None,
    zone_transfer_vulnerable: bool = False,
    zone_transfer_records: Optional[list[str]] = None,
    http_findings: Optional[list[HttpFinding]] = None,
    findings: Optional[list[Finding]] = None,
    modules_run: Optional[list[str]] = None,
    errors: Optional[dict[str, str]] = None,
) -> ScanReport:
    """Assemble all scan module outputs into a final ScanReport."""
    try:
        ports = ports or []
        dns_records = dns_records or []
        subdomains = subdomains or []
        zone_transfer_records = zone_transfer_records or []
        http_findings = http_findings or []
        findings = findings or []
        errors = errors or {}
        # Use the caller-supplied list when available; fall back to inference
        # only for backwards compatibility with direct calls that omit it.
        if modules_run is not None:
            actual_modules_run = list(modules_run)
        else:
            # Legacy inference from outputs (less accurate but kept for
            # callers that don't pass the explicit list).
            actual_modules_run = []
            if ports:
                actual_modules_run.append("port_scanner")
            if any(getattr(p, "cves", []) for p in ports):
                actual_modules_run.append("cve_lookup")
            if dns_records or subdomains:
                actual_modules_run.append("dns_enum")
            if osint is not None and any([
                osint.whois,
                osint.shodan_ports,
                osint.shodan_vulns,
                osint.certificates,
                osint.subdomains_from_certs,
            ]):
                actual_modules_run.append("osint_fetcher")
            if http_findings:
                actual_modules_run.append("service_probe")

        cves = _collect_all_cves(ports)
        score = calculate_risk_score(
            cves,
            len(ports),
            http_findings,
            osint=osint,
            zone_transfer_vulnerable=zone_transfer_vulnerable,
            findings=findings,
        )
        risk_label = get_risk_label(score)
        severity_summary = _build_severity_summary(cves, findings)
        top_findings = _get_top_findings(cves)
        subdomains = _merge_subdomains(subdomains, osint)

        started_dt = _parse_started_at(started_at)
        now = datetime.now(timezone.utc)
        scan_duration_seconds = None
        if started_dt:
            scan_duration_seconds = round((now - started_dt).total_seconds(), 2)

        report = ScanReport(
            scan_id=scan_id,
            target=target,
            status=ScanStatus.COMPLETE,
            risk_score=score,
            risk_label=risk_label,
            severity_summary=severity_summary,
            ports=ports,
            cves=cves,
            dns_records=dns_records,
            subdomains=subdomains,
            zone_transfer_vulnerable=zone_transfer_vulnerable,
            zone_transfer_records=zone_transfer_records,
            osint=osint,
            http_findings=http_findings,
            findings=findings,
            top_findings=top_findings,
            started_at=started_at,
            completed_at=now.isoformat(),
            scan_duration_seconds=scan_duration_seconds,
            modules_run=actual_modules_run,
            errors=errors,
        )
        return report
    except Exception as exc:
        logger.error("report_gen: failed to assemble scan report: %s", exc)
        return ScanReport(
            scan_id=scan_id or str(uuid.uuid4()),
            target=target,
            status=ScanStatus.FAILED,
            risk_score=None,
            risk_label=None,
            severity_summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
            ports=ports or [],
            cves=[],
            dns_records=dns_records or [],
            subdomains=subdomains or [],
            osint=osint,
            http_findings=http_findings or [],
            findings=findings or [],
            top_findings=[],
            started_at=started_at,
            completed_at=datetime.now(timezone.utc).isoformat(),
            scan_duration_seconds=None,
            modules_run=[],
            errors={**(errors or {}), "report_gen": str(exc)},
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    demo_ports = [
        PortResult(port=80, protocol="tcp", state="open", service="http", product="nginx", version="1.20.0", banner="nginx/1.20.0"),
        PortResult(port=443, protocol="tcp", state="open", service="https", product="Apache", version="2.4.54", banner="Apache/2.4.54"),
    ]
    demo_ports[0].cves = [
        CVEResult(
            cve_id="CVE-2024-0001",
            description="Example critical vulnerability.",
            cvss_score=9.8,
            cvss_version="3.1",
            severity="CRITICAL",
            published_date="2024-01-01",
            references=["https://example.com/CVE-2024-0001"],
        )
    ]
    demo_ports[1].cves = [
        CVEResult(
            cve_id="CVE-2024-0002",
            description="Example high severity vulnerability.",
            cvss_score=7.5,
            cvss_version="3.1",
            severity="HIGH",
            published_date="2024-02-01",
            references=["https://example.com/CVE-2024-0002"],
        )
    ]
    demo_report = generate_report(
        scan_id=str(uuid.uuid4()),
        target="example.com",
        started_at=datetime.now(timezone.utc).isoformat(),
        ports=demo_ports,
        osint=None,
        dns_records=[DNSRecord(record_type="A", name="example.com", value="93.184.216.34", ttl=3600)],
        subdomains=[SubdomainResult(subdomain="www.example.com", ip_address="93.184.216.34", is_different_ip=False)],
        http_findings=[HttpFinding(url="http://example.com", status_code=200, server_header="nginx/1.20.0", powered_by=None, cms_detected=None, missing_headers=["Content-Security-Policy", "Strict-Transport-Security"], cert=None)],
        errors={},
    )
    print(demo_report.model_dump_json(indent=2))
