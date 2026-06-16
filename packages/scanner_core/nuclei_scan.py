"""
nuclei_scan.py
--------------
Template-based vulnerability scanning via ProjectDiscovery's `nuclei`.
Runs nuclei against discovered HTTP service URLs and maps each JSONL result
to a Finding. Like the Shodan/NVD integrations, this degrades gracefully:
if the `nuclei` binary is not installed, it logs a warning and returns [].

Install nuclei: https://github.com/projectdiscovery/nuclei (a single Go binary,
on PATH — same model as the required `nmap` binary).
"""

import json
import logging
import shutil
import subprocess

try:
    from .models import Finding
except ImportError:  # pragma: no cover
    from models import Finding

logger = logging.getLogger(__name__)

NUCLEI_TIMEOUT_SECONDS = 240
NUCLEI_SEVERITIES = "low,medium,high,critical"
MAX_TARGETS = 5


def is_nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def _map_severity(value: str) -> str:
    v = (value or "").strip().upper()
    return v if v in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "INFO"


def _parse_line(line: str) -> Finding | None:
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    info = obj.get("info", {}) if isinstance(obj, dict) else {}
    name = info.get("name") or obj.get("template-id") or "Nuclei finding"
    refs = info.get("reference") or []
    if isinstance(refs, str):
        refs = [refs]
    return Finding(
        title=str(name),
        severity=_map_severity(info.get("severity", "info")),
        category="nuclei",
        description=info.get("description") or "",
        target=obj.get("matched-at") or obj.get("host") or obj.get("matched"),
        evidence=obj.get("template-id"),
        remediation=info.get("remediation"),
        source="nuclei_scan",
        references=[r for r in refs if isinstance(r, str)],
    )


def scan_with_nuclei(urls: list[str]) -> list[Finding]:
    """Run nuclei against the given URLs and return findings (or [] if absent)."""
    targets = [u for u in (urls or []) if u][:MAX_TARGETS]
    if not targets:
        return []
    if not is_nuclei_available():
        logger.warning("nuclei_scan: nuclei binary not found on PATH — skipping template scan")
        return []

    cmd = [
        "nuclei", "-jsonl", "-silent", "-no-color", "-disable-update-check",
        "-severity", NUCLEI_SEVERITIES, "-timeout", "5", "-rate-limit", "100",
    ]
    try:
        proc = subprocess.run(
            cmd,
            input="\n".join(targets),
            capture_output=True,
            text=True,
            timeout=NUCLEI_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        logger.warning("nuclei_scan: nuclei timed out after %ss", NUCLEI_TIMEOUT_SECONDS)
        return []
    except Exception as exc:
        logger.warning("nuclei_scan: nuclei execution failed: %s", exc)
        return []

    findings: list[Finding] = []
    for line in proc.stdout.splitlines():
        finding = _parse_line(line)
        if finding is not None:
            findings.append(finding)
    logger.info("nuclei_scan: %d findings across %d targets", len(findings), len(targets))
    return findings
