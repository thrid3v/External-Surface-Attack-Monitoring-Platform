"""
web_audit.py
------------
Active (but read-only) web exposure checks against discovered HTTP services.
Where service_probe.py records technology/headers, this module looks for
concrete misconfigurations and exposures and returns Finding objects:

  - Sensitive files/paths: /.git/HEAD, /.env, /server-status, phpinfo, actuator,
    swagger/openapi docs, common backups
  - Directory listing enabled
  - CORS misconfiguration (reflected origin, or wildcard with credentials)
  - Missing cookie flags (HttpOnly / Secure / SameSite)
  - Clickjacking exposure (no X-Frame-Options and no CSP frame-ancestors)

All requests are plain GETs with a short timeout; nothing is modified.
"""

import logging
import warnings
from typing import Iterable

import httpx
import urllib3

try:
    from .models import Finding, PortResult
except ImportError:  # pragma: no cover
    from models import Finding, PortResult

from .http_common import USER_AGENT, base_urls, get

logger = logging.getLogger(__name__)

MAX_BASE_URLS = 2  # bound path probing across services

warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)


# path, title, severity, signature substring (lowercased) the body must contain, remediation
PATH_CHECKS: list[tuple[str, str, str, str, str]] = [
    ("/.git/HEAD", "Exposed Git repository", "HIGH", "ref:", "Block access to the .git directory at the web server."),
    ("/.env", "Exposed environment file", "CRITICAL", "=", "Remove .env from the web root and rotate any leaked secrets."),
    ("/.svn/entries", "Exposed SVN metadata", "MEDIUM", "", "Block access to .svn directories."),
    ("/server-status", "Apache mod_status exposed", "MEDIUM", "apache server status", "Restrict /server-status to localhost."),
    ("/phpinfo.php", "phpinfo() exposed", "MEDIUM", "php version", "Remove phpinfo pages from production."),
    ("/actuator/health", "Spring Boot actuator exposed", "MEDIUM", "status", "Secure or disable actuator endpoints."),
    ("/swagger.json", "API documentation exposed", "LOW", "swagger", "Restrict API docs in production."),
    ("/openapi.json", "API documentation exposed", "LOW", "openapi", "Restrict API docs in production."),
    ("/.DS_Store", "Exposed .DS_Store file", "LOW", "", "Remove .DS_Store files from the web root."),
]


def _check_paths(client: httpx.Client, base: str) -> list[Finding]:
    findings: list[Finding] = []
    for path, title, severity, signature, remediation in PATH_CHECKS:
        resp = get(client, base + path)
        if resp is None or resp.status_code != 200:
            continue
        body = (resp.text or "")[:4000].lower()
        if signature and signature not in body:
            continue
        # crude soft-404 guard: skip if it looks like an HTML error page
        if not signature and ("<html" in body and "not found" in body):
            continue
        findings.append(Finding(
            title=title,
            severity=severity,
            category="web_exposure",
            description=f"{title} is reachable at {base}{path}.",
            target=base + path,
            evidence=f"HTTP 200 at {path}",
            remediation=remediation,
            source="web_audit",
        ))
    return findings


def _check_root(client: httpx.Client, base: str) -> list[Finding]:
    findings: list[Finding] = []
    resp = get(client, base + "/")
    if resp is None:
        return findings
    body = (resp.text or "")[:4000].lower()
    headers = {k.lower(): v for k, v in resp.headers.items()}

    if "index of /" in body:
        findings.append(Finding(
            title="Directory listing enabled",
            severity="MEDIUM",
            category="web_exposure",
            description="The server returns an auto-generated directory index.",
            target=base + "/",
            remediation="Disable autoindex / directory listing.",
            source="web_audit",
        ))

    # Clickjacking
    csp = headers.get("content-security-policy", "")
    if "x-frame-options" not in headers and "frame-ancestors" not in csp.lower():
        findings.append(Finding(
            title="Clickjacking exposure",
            severity="LOW",
            category="web_exposure",
            description="No X-Frame-Options header and no CSP frame-ancestors directive.",
            target=base + "/",
            remediation="Set X-Frame-Options: DENY or a CSP frame-ancestors policy.",
            source="web_audit",
        ))

    # Cookie flags
    set_cookie = resp.headers.get("set-cookie")
    if set_cookie:
        lowered = set_cookie.lower()
        missing = [flag for flag, token in (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite")) if token not in lowered]
        if base.startswith("http://") and "Secure" in missing:
            missing.remove("Secure")  # Secure not applicable over plain http
        if missing:
            findings.append(Finding(
                title=f"Cookie missing {', '.join(missing)} flag(s)",
                severity="LOW",
                category="web_exposure",
                description="A Set-Cookie response is missing recommended security attributes.",
                target=base + "/",
                remediation="Set HttpOnly, Secure, and SameSite on session cookies.",
                source="web_audit",
            ))

    # CORS
    cors = get(client, base + "/", headers={"Origin": "https://evil.example"})
    if cors is not None:
        ch = {k.lower(): v for k, v in cors.headers.items()}
        acao = ch.get("access-control-allow-origin", "")
        acac = ch.get("access-control-allow-credentials", "").lower()
        if acao == "https://evil.example":
            findings.append(Finding(
                title="CORS reflects arbitrary origin",
                severity="HIGH" if acac == "true" else "MEDIUM",
                category="web_exposure",
                description="The server reflects an attacker-controlled Origin in Access-Control-Allow-Origin"
                + (" with credentials enabled." if acac == "true" else "."),
                target=base + "/",
                evidence=f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac or 'false'}",
                remediation="Validate Origin against an allowlist; never reflect arbitrary origins with credentials.",
                source="web_audit",
            ))
        elif acao == "*" and acac == "true":
            findings.append(Finding(
                title="CORS wildcard with credentials",
                severity="MEDIUM",
                category="web_exposure",
                description="Access-Control-Allow-Origin: * combined with credentials.",
                target=base + "/",
                source="web_audit",
            ))

    return findings


def audit_web(host: str, ports: Iterable[PortResult]) -> list[Finding]:
    """Run web exposure checks against the host's HTTP services."""
    bases = base_urls(host, list(ports))[:MAX_BASE_URLS]
    if not bases:
        return []
    findings: list[Finding] = []
    with httpx.Client(verify=False, headers={"User-Agent": USER_AGENT}) as client:
        for base in bases:
            try:
                findings.extend(_check_root(client, base))
                findings.extend(_check_paths(client, base))
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("web_audit: audit failed for %s: %s", base, exc)
    logger.info("web_audit: %d findings for %s", len(findings), host)
    return findings


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from .models import PortResult as PR
    res = audit_web("scanme.nmap.org", [PR(port=80, protocol="tcp", state="open", service="http")])
    for f in res:
        print(f.severity, f.title, "->", f.target)
