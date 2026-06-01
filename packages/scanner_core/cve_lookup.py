"""
cve_lookup.py
-------------
Takes a service name and version string discovered by port_scanner.py
and queries the NVD (National Vulnerability Database) REST API v2.0
to find matching CVEs with their severity scores.
 
This module is what turns raw scan data into actionable security findings.
 
CONTAINS:
  - lookup_cves(service: str, version: str) -> list[CVEResult]
 
    Queries NVD for CVEs matching the given software and version.
 
    Arguments:
      service : the product name e.g. "Apache httpd", "OpenSSH", "nginx"
      version : the version string e.g. "2.4.51", "7.4", "1.18.0"
 
    Returns:
      list[CVEResult] — each item contains:
        - cve_id        e.g. "CVE-2021-41773"
        - description   plain English description of the vulnerability
        - cvss_score    float 0.0 - 10.0
        - cvss_version  "3.1" or "2.0"
        - severity      "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        - published     date the CVE was published
        - references    list of URLs for further reading
 
    How it works:
      1. Clean and normalise the service/version strings before querying
         (NVD is picky — "Apache httpd" works, "apache" may not)
      2. Hit the NVD REST API endpoint:
         https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service+version}
      3. Parse the JSON response into CVEResult objects
      4. Sort results by CVSS score descending before returning
 
  - get_severity_label(cvss_score: float) -> str
 
    Helper that converts a numeric CVSS score to a severity label:
      9.0 - 10.0  → CRITICAL
      7.0 - 8.9   → HIGH
      4.0 - 6.9   → MEDIUM
      0.1 - 3.9   → LOW
      0.0         → NONE
 
IMPORTANT:
  - NVD rate limits unauthenticated requests to 5 per 30 seconds.
    Add an NVD_API_KEY to .env for 50 requests per 30 seconds (free to register).
    Use time.sleep(0.6) between calls if no API key is set.
  - Cache results in memory per (service, version) pair during a single scan
    to avoid duplicate API calls when multiple ports run the same software.
  - Handle HTTP 503 from NVD gracefully — it goes down occasionally.
    Return an empty list with a warning log, do not crash the scan.
 
EXAMPLE USAGE:
  from scanner_core.cve_lookup import lookup_cves
  cves = lookup_cves("Apache httpd", "2.4.51")
  for cve in cves:
      print(cve.cve_id, cve.cvss_score, cve.severity)
"""

import logging
import os
import time
import urllib.parse
from typing import Any, Optional

import requests
from dotenv import load_dotenv

try:
    from .models import CVEResult
except ImportError:
    from models import CVEResult

logger = logging.getLogger(__name__)

load_dotenv()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_RATE_LIMIT_DELAY = 0.6
REQUEST_TIMEOUT_SECONDS = 10
_CVE_CACHE: dict[tuple[str, str], list[CVEResult]] = {}


def get_severity_label(cvss_score: float) -> str:
    """Convert a CVSS score into a standardized severity label."""
    if cvss_score >= 9.0:
        return "CRITICAL"
    if cvss_score >= 7.0:
        return "HIGH"
    if cvss_score >= 4.0:
        return "MEDIUM"
    if cvss_score > 0.0:
        return "LOW"
    return "NONE"


def _clean_query_term(value: str) -> str:
    """Normalize search terms for NVD keyword search."""
    trimmed = value.strip()
    lowercase = trimmed.lower()
    cleaned = " ".join(part for part in lowercase.split() if part)
    return cleaned


def _build_keyword_search(service: str, version: str) -> str:
    """Build a keywordSearch query string for the NVD API."""
    components = []
    if service:
        components.append(_clean_query_term(service))
    if version:
        components.append(_clean_query_term(version))
    return " ".join(components)


def _extract_cvss(vuln_item: dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
    """Extract CVSS score and version from NVD vulnerability JSON."""
    metrics = vuln_item.get("metrics", {})
    if not isinstance(metrics, dict):
        metrics = {}
    if not metrics:
        cve_data = vuln_item.get("cve", {})
        if isinstance(cve_data, dict):
            metrics = cve_data.get("metrics", {}) or {}
    for score_type in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(score_type)
        if isinstance(entries, list) and entries:
            first = entries[0].get("cvssData", {})
            score = first.get("baseScore")
            version = first.get("version")
            if score is not None:
                try:
                    return float(score), str(version)
                except (TypeError, ValueError):
                    continue
    return None, None


def _parse_cve_item(item: dict[str, Any]) -> CVEResult | None:
    """Convert a single NVD CVE JSON item into a CVEResult."""
    cve_data = item.get("cve", {})
    if not isinstance(cve_data, dict):
        return None

    cve_id = cve_data.get("id")
    description_data = cve_data.get("descriptions", [])
    description = ""
    if isinstance(description_data, list):
        for entry in description_data:
            if entry.get("lang") == "en":
                description = entry.get("value", "")
                break
    if not cve_id or not description:
        return None

    score, version = _extract_cvss(item)
    severity = get_severity_label(score if score is not None else 0.0)
    references = []
    ref_items = cve_data.get("references", {})
    if isinstance(ref_items, dict):
        ref_items = ref_items.get("references", [])
    if isinstance(ref_items, list):
        for ref in ref_items:
            if not isinstance(ref, dict):
                continue
            url = ref.get("url")
            if isinstance(url, str) and url:
                references.append(url)

    published_date = item.get("published") or item.get("publishedDate")
    return CVEResult(
        cve_id=str(cve_id),
        description=description,
        cvss_score=score,
        cvss_version=version,
        severity=severity,
        published_date=str(published_date) if published_date else None,
        references=references,
    )


def _query_nvd(keyword_search: str) -> list[CVEResult]:
    """Query the NVD API and return parsed CVE results."""
    params = {"keywordSearch": keyword_search}
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        response = requests.get(
            NVD_API_BASE,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except Exception as e:
        logger.warning("cve_lookup: NVD request failed: %s", e)
        return []

    if not NVD_API_KEY:
        time.sleep(NVD_RATE_LIMIT_DELAY)

    if response.status_code == 503:
        logger.warning("cve_lookup: NVD service unavailable (503)")
        return []
    if response.status_code == 429:
        logger.warning("cve_lookup: NVD rate limit exceeded (429)")
        return []
    if response.status_code >= 400:
        logger.warning(
            "cve_lookup: NVD returned status %s for query %s",
            response.status_code,
            keyword_search,
        )
        return []

    try:
        body = response.json()
    except ValueError as e:
        logger.warning("cve_lookup: failed to decode NVD JSON response: %s", e)
        return []

    results: list[CVEResult] = []
    for item in body.get("vulnerabilities", []):
        cve_result = _parse_cve_item(item)
        if cve_result is not None:
            results.append(cve_result)

    results.sort(key=lambda item: item.cvss_score or 0.0, reverse=True)
    logger.info("cve_lookup: found %d CVEs for query %s", len(results), keyword_search)
    return results


def lookup_cves(service: str, version: str) -> list[CVEResult]:
    """Look up CVEs for a service and version using the NVD API."""
    normalized_service = service.strip()
    normalized_version = version.strip()
    if not normalized_service or not normalized_version:
        logger.warning(
            "cve_lookup: missing service or version, skipping CVE lookup for %s %s",
            service,
            version,
        )
        return []

    cache_key = (normalized_service.lower(), normalized_version.lower())
    if cache_key in _CVE_CACHE:
        logger.debug(
            "cve_lookup: returning cached CVEs for %s %s",
            normalized_service,
            normalized_version,
        )
        return _CVE_CACHE[cache_key]

    keyword_search = _build_keyword_search(normalized_service, normalized_version)
    if not keyword_search:
        return []

    results = _query_nvd(keyword_search)
    _CVE_CACHE[cache_key] = results
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    demo_service = "Apache httpd"
    demo_version = "2.4.51"
    logger.info(
        "cve_lookup: running standalone lookup for %s %s",
        demo_service,
        demo_version,
    )
    found = lookup_cves(demo_service, demo_version)
    if not found:
        print("No CVEs found or lookup failed.")
    for cve in found:
        print(
            f"{cve.cve_id}: {cve.severity} {cve.cvss_score} - {cve.description[:120]}"
        )
