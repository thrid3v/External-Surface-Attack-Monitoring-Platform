"""
services/diff.py
----------------
Compare two scan reports (the parsed ``result_json`` dicts) and summarize what
changed between them: new/resolved CVEs, opened/closed ports, and risk delta.
Used by the scan diff endpoint and by alert generation in the worker.
"""

from typing import Any, Optional


def _cve_map(report: Optional[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if not report:
        return {}
    return {c.get("cve_id"): c for c in (report.get("cves") or []) if c.get("cve_id")}


def _port_set(report: Optional[dict[str, Any]]) -> set[int]:
    if not report:
        return set()
    return {p.get("port") for p in (report.get("ports") or []) if p.get("port") is not None}


def _slim_cve(cve: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": cve.get("cve_id"),
        "severity": cve.get("severity"),
        "cvss_score": cve.get("cvss_score"),
    }


def diff_reports(old: Optional[dict[str, Any]], new: dict[str, Any]) -> dict[str, Any]:
    """Return a structured diff of ``new`` relative to ``old`` (may be None)."""
    old_cves = _cve_map(old)
    new_cves = _cve_map(new)

    new_cve_ids = set(new_cves) - set(old_cves)
    resolved_cve_ids = set(old_cves) - set(new_cves)

    old_ports = _port_set(old)
    new_ports = _port_set(new)

    current_risk = new.get("risk_score")
    previous_risk = old.get("risk_score") if old else None
    risk_delta = (
        current_risk - previous_risk
        if isinstance(current_risk, int) and isinstance(previous_risk, int)
        else None
    )

    return {
        "compared_to": (old or {}).get("scan_id"),
        "current_risk": current_risk,
        "previous_risk": previous_risk,
        "risk_delta": risk_delta,
        "new_cves": [_slim_cve(new_cves[i]) for i in sorted(new_cve_ids)],
        "resolved_cves": [_slim_cve(old_cves[i]) for i in sorted(resolved_cve_ids)],
        "opened_ports": sorted(new_ports - old_ports),
        "closed_ports": sorted(old_ports - new_ports),
    }
