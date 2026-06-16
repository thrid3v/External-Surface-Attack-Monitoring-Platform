"""
takeover.py
-----------
Subdomain takeover detection. For each known subdomain it resolves the CNAME
chain and flags two conditions:

  - The CNAME points at a third-party service (S3, GitHub Pages, Heroku, ...)
    whose page returns a known "unclaimed resource" fingerprint  -> HIGH (confirmed)
  - The CNAME target itself does not resolve (dangling CNAME)          -> HIGH

Pointing at a known service without the fingerprint is reported as MEDIUM
(potential takeover worth manual review).
"""

import logging

import dns.exception
import dns.resolver
import httpx

try:
    from .models import Finding
except ImportError:  # pragma: no cover
    from models import Finding

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 6
MAX_SUBDOMAINS = 40
USER_AGENT = "Mozilla/5.0 (compatible; EASM-Scanner/1.0)"

# cname substring -> (service name, body fingerprint indicating an unclaimed resource)
FINGERPRINTS: list[tuple[str, str, str]] = [
    ("github.io", "GitHub Pages", "there isn't a github pages site here"),
    ("herokuapp.com", "Heroku", "no such app"),
    ("s3.amazonaws.com", "AWS S3", "nosuchbucket"),
    ("amazonaws.com", "AWS S3", "nosuchbucket"),
    ("azurewebsites.net", "Azure", "404 web site not found"),
    ("cloudapp.net", "Azure", "404 web site not found"),
    ("fastly.net", "Fastly", "fastly error: unknown domain"),
    ("pantheonsite.io", "Pantheon", "the gods are wise"),
    ("surge.sh", "Surge", "project not found"),
    ("bitbucket.io", "Bitbucket", "repository not found"),
    ("readthedocs.io", "Read the Docs", "unknown to read the docs"),
    ("zendesk.com", "Zendesk", "help center closed"),
    ("ghost.io", "Ghost", "the thing you were looking for is no longer here"),
    ("wordpress.com", "WordPress", "do you want to register"),
]


def _resolve_cname(name: str) -> str | None:
    try:
        answer = dns.resolver.resolve(name, "CNAME")
        return str(answer[0].target).rstrip(".").lower()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None


def _resolves(name: str) -> bool:
    try:
        dns.resolver.resolve(name, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except Exception:
        return True  # be conservative: unknown errors are not "dangling"


def _fetch_body(name: str) -> str:
    for scheme in ("https", "http"):
        try:
            resp = httpx.get(f"{scheme}://{name}", timeout=HTTP_TIMEOUT, verify=False,
                             follow_redirects=True, headers={"User-Agent": USER_AGENT})
            return (resp.text or "")[:4000].lower()
        except Exception:
            continue
    return ""


def check_takeover(name: str) -> Finding | None:
    cname = _resolve_cname(name)
    if not cname:
        return None

    # Dangling CNAME: target no longer resolves -> strong takeover signal.
    if not _resolves(cname):
        return Finding(
            title="Dangling CNAME (possible subdomain takeover)",
            severity="HIGH",
            category="takeover",
            description=f"{name} is a CNAME to {cname}, which no longer resolves.",
            target=name,
            evidence=f"CNAME -> {cname} (NXDOMAIN)",
            remediation="Remove the dangling DNS record or reclaim the target resource.",
            source="takeover_check",
        )

    for pattern, service, fingerprint in FINGERPRINTS:
        if pattern in cname:
            body = _fetch_body(name)
            confirmed = fingerprint and fingerprint in body
            return Finding(
                title=f"Subdomain takeover via {service}" if confirmed else f"Potential {service} takeover",
                severity="HIGH" if confirmed else "MEDIUM",
                category="takeover",
                description=(
                    f"{name} points to {service} ({cname}) and returns the unclaimed-resource fingerprint."
                    if confirmed
                    else f"{name} points to {service} ({cname}); verify the resource is claimed."
                ),
                target=name,
                evidence=f"CNAME -> {cname}",
                remediation="Claim the resource on the provider or remove the DNS record.",
                source="takeover_check",
            )
    return None


def check_takeovers(subdomains: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for name in (subdomains or [])[:MAX_SUBDOMAINS]:
        try:
            finding = check_takeover(name)
            if finding:
                findings.append(finding)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("takeover: check failed for %s: %s", name, exc)
    logger.info("takeover: %d findings across %d subdomains", len(findings), min(len(subdomains or []), MAX_SUBDOMAINS))
    return findings
