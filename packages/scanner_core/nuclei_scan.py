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
import os
import shutil
import subprocess
import sys
from pathlib import Path

try:
    from .models import Finding
except ImportError:  # pragma: no cover
    from models import Finding

logger = logging.getLogger(__name__)

NUCLEI_TIMEOUT_SECONDS = 240
NUCLEI_SEVERITIES = "low,medium,high,critical"
MAX_TARGETS = 5


def _nuclei_path() -> str | None:
    """Resolve the nuclei binary, independent of venv activation.

    Resolution order:
      1. ``NUCLEI_PATH`` env override (explicit operator control).
      2. Next to the running interpreter (a venv's Scripts/bin dir) — this is
         where we install it, and it works even when the venv isn't "activated"
         on PATH (e.g. Celery launched by absolute path).
      3. Anywhere on PATH.
    """
    override = os.getenv("NUCLEI_PATH")
    if override and Path(override).exists():
        return override

    binary = "nuclei.exe" if os.name == "nt" else "nuclei"
    local = Path(sys.executable).parent / binary
    if local.exists():
        return str(local)

    return shutil.which("nuclei")


def is_nuclei_available() -> bool:
    return _nuclei_path() is not None


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
    nuclei_bin = _nuclei_path()
    if nuclei_bin is None:
        logger.warning("nuclei_scan: nuclei binary not found — skipping template scan")
        return []

    cmd = [
        nuclei_bin, "-jsonl", "-silent", "-no-color", "-disable-update-check",
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
