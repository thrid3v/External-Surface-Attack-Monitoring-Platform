"""
email_audit.py
--------------
Email security posture from DNS: grades SPF and DMARC records (which govern
whether a domain can be spoofed in phishing). DKIM needs a selector we can't
guess reliably, so it is not checked here.
"""

import logging

import dns.exception
import dns.resolver

try:
    from .models import Finding
except ImportError:  # pragma: no cover
    from models import Finding

logger = logging.getLogger(__name__)


def _txt_records(name: str) -> list[str]:
    try:
        answer = dns.resolver.resolve(name, "TXT")
        return [str(r).strip('"') for r in answer]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception as exc:
        logger.debug("email_audit: TXT lookup failed for %s: %s", name, exc)
        return []


def audit_email(domain: str) -> list[Finding]:
    """Return findings for missing/weak SPF and DMARC records."""
    domain = domain.strip().lower()
    findings: list[Finding] = []

    # --- SPF ---
    spf = next((t for t in _txt_records(domain) if t.lower().startswith("v=spf1")), None)
    if spf is None:
        findings.append(Finding(
            title="No SPF record",
            severity="MEDIUM",
            category="email",
            description=f"{domain} has no SPF record, allowing the domain to be spoofed in email.",
            target=domain,
            remediation="Publish an SPF TXT record ending in -all (hardfail).",
            source="email_audit",
        ))
    elif "+all" in spf.lower():
        findings.append(Finding(
            title="Permissive SPF (+all)",
            severity="HIGH",
            category="email",
            description=f"{domain}'s SPF uses +all, authorizing any host to send mail as the domain.",
            target=domain,
            evidence=spf,
            remediation="Replace +all with -all and an explicit sender list.",
            source="email_audit",
        ))

    # --- DMARC ---
    dmarc_records = _txt_records(f"_dmarc.{domain}")
    dmarc = next((t for t in dmarc_records if t.lower().startswith("v=dmarc1")), None)
    if dmarc is None:
        findings.append(Finding(
            title="No DMARC record",
            severity="MEDIUM",
            category="email",
            description=f"{domain} has no DMARC policy, so spoofed mail is not rejected or reported.",
            target=domain,
            remediation="Publish a _dmarc TXT record with at least p=quarantine.",
            source="email_audit",
        ))
    elif "p=none" in dmarc.lower().replace(" ", ""):
        findings.append(Finding(
            title="DMARC policy is none (monitoring only)",
            severity="LOW",
            category="email",
            description=f"{domain}'s DMARC policy is p=none, which only monitors and does not block spoofing.",
            target=domain,
            evidence=dmarc,
            remediation="Move DMARC to p=quarantine or p=reject once aligned.",
            source="email_audit",
        ))

    logger.info("email_audit: %d findings for %s", len(findings), domain)
    return findings
