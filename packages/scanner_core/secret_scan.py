"""
secret_scan.py
--------------
Detects exposed secrets and credentials on a target's web surface. Fetches
reachable HTML pages, their linked JS/text assets, and a curated set of exposed
config/.env/.git files, then scans every text body for hardcoded secrets using
curated provider patterns plus an assignment-context entropy check.

All matched secrets are REDACTED in finding evidence. The module is read-only
(GET only), hard-bounded by page/asset caps and a wall-clock deadline, and never
raises out to the worker. Shared HTTP helpers come from http_common.
"""

import logging
import math
import re
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

try:
    from .models import Finding
except ImportError:  # pragma: no cover
    from models import Finding

from .http_common import get

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 8
MAX_BASE_URLS = 2
MAX_PAGES_CRAWLED = 10
MAX_ASSETS = 25
MAX_BYTES_PER_RESOURCE = 2_000_000
MODULE_DEADLINE_SECONDS = 45
ENTROPY_MIN = 4.0
ENTROPY_MIN_LEN = 20

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.dev",
    "/config.json", "/config.yaml", "/config.yml",
    "/credentials", "/.aws/credentials", "/secrets.json",
]
GIT_PATHS = ["/.git/config", "/.git/HEAD"]
TEXT_EXTENSIONS = (".js", ".json", ".txt", ".map", ".yml", ".yaml", ".env", ".config", ".xml", ".ts")

# (name, severity, compiled pattern). Patterns are deliberately specific to keep
# false positives low; generic/unknown tokens are handled by gated entropy.
SECRET_PATTERNS: list[tuple[str, str, "re.Pattern[str]"]] = [
    ("AWS secret access key", "CRITICAL", re.compile(r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("AWS access key ID", "HIGH", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", "HIGH", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("GCP service account key", "CRITICAL", re.compile(r'"type"\s*:\s*"service_account"')),
    ("Stripe secret key", "HIGH", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Slack token", "HIGH", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub token", "HIGH", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("SendGrid API key", "HIGH", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("Twilio API key", "HIGH", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Private key (PEM)", "CRITICAL", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Database connection string with credentials", "CRITICAL", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@[^\s/'\"]+")),
    ("JSON Web Token (JWT)", "MEDIUM", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
]

ASSIGNMENT_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)"
    r"['\"]?\s*[:=]\s*['\"]([^'\"\s]{%d,})['\"]" % ENTROPY_MIN_LEN
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(secret: str) -> str:
    s = (secret or "").strip()
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}{'*' * 8}{s[-4:]}"


def _finding(title: str, severity: str, target: str, evidence: str) -> Finding:
    return Finding(
        title=f"Exposed secret: {title}",
        severity=severity,
        category="secret_exposure",
        description=f"A {title} was found in content served at {target}.",
        target=target,
        evidence=f"Match (redacted): {evidence}",
        remediation="Rotate the exposed credential immediately and remove it from web-served content; load secrets from server-side config or a secrets manager.",
        source="secret_scan",
    )


def _exposure_finding(url: str) -> Finding:
    return Finding(
        title="Exposed sensitive file",
        severity="MEDIUM",
        category="secret_exposure",
        description=f"A sensitive file is publicly reachable at {url}.",
        target=url,
        evidence="HTTP 200",
        remediation="Block public access to this file at the web server and rotate any secrets it contained.",
        source="secret_scan",
    )


def _scan_content(url: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    reported: set[str] = set()  # redacted values already reported (dedup pattern + entropy)
    snippet = (content or "")[:MAX_BYTES_PER_RESOURCE]

    for name, severity, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(snippet):
            redacted = _redact(match.group(0))
            if redacted in reported:
                continue
            reported.add(redacted)
            findings.append(_finding(name, severity, url, redacted))

    for match in ASSIGNMENT_RE.finditer(snippet):
        value = match.group(1)
        if len(value) < ENTROPY_MIN_LEN or _shannon_entropy(value) < ENTROPY_MIN:
            continue
        redacted = _redact(value)
        if redacted in reported:
            continue
        reported.add(redacted)
        findings.append(_finding("High-entropy secret in assignment", "MEDIUM", url, redacted))

    return findings


class _AssetExtractor(HTMLParser):
    """Collect script/link asset URLs and anchor page links from an HTML page."""

    def __init__(self) -> None:
        super().__init__()
        self.assets: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.assets.append(a["src"])
        elif tag == "link" and a.get("href"):
            self.assets.append(a["href"])
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)


@dataclass
class _Budget:
    deadline: float
    assets_left: int

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline


def _is_text_like(resp: httpx.Response, url: str) -> bool:
    ctype = resp.headers.get("content-type", "").lower()
    if any(t in ctype for t in ("text", "javascript", "json", "xml", "yaml")):
        return True
    path = urlparse(url).path.lower()
    return path.endswith(TEXT_EXTENSIONS)


def _body(resp: httpx.Response) -> str:
    return (resp.text or "")[:MAX_BYTES_PER_RESOURCE]


def _scan_url(
    client: httpx.Client,
    url: str,
    scanned: set[str],
    findings: list[Finding],
) -> Optional[httpx.Response]:
    """Fetch `url` once; if it returns 200 with a text-like body, scan it for
    secrets (appending to `findings`). Returns the response so the caller can
    extract assets/links, or None if already scanned / not fetched."""
    if url in scanned:
        return None
    scanned.add(url)
    resp = get(client, url, timeout=HTTP_TIMEOUT)
    if resp is None or resp.status_code != 200:
        return None
    if _is_text_like(resp, url):
        findings.extend(_scan_content(url, _body(resp)))
    return resp
