"""
notifications.py
----------------
Out-of-band delivery of change-detection alerts.

``deliver_alert`` loads the alert owner's :class:`NotificationSettings`, applies
the per-user severity threshold, and fans out to each enabled channel. Channel
sends are best-effort: a failure in one channel is logged and never raised into
the caller (a slow SMTP server must never break a scan or another channel).

SMTP transport is configured server-side via environment variables; the per-user
row only decides *whether* and *where* to deliver.
"""

import ipaddress
import logging
import os
import smtplib
import socket
from email.message import EmailMessage
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from db.models import Alert, NotificationSettings

logger = logging.getLogger(__name__)


class WebhookURLNotAllowed(ValueError):
    """Raised when a webhook URL targets a non-public address (SSRF guard)."""


def _resolve_ips(host: str) -> list[str]:
    """Resolve a hostname to its IP addresses (empty list on failure)."""
    try:
        return [info[4][0] for info in socket.getaddrinfo(host, None)]
    except (socket.gaierror, UnicodeError):
        return []


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def validate_webhook_url(url: str | None) -> None:
    """Reject webhook URLs that aren't http(s) to a public address.

    Prevents server-side request forgery: a user must not be able to make the
    server POST to loopback, RFC-1918, link-local (e.g. 169.254.169.254 cloud
    metadata), or otherwise-internal addresses.
    """
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise WebhookURLNotAllowed(f"Webhook URL must be a valid http(s) URL: {url!r}")
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
        ips = [host]  # literal IP — check it directly, no DNS
    except ValueError:
        ips = _resolve_ips(host)
    if not ips:
        raise WebhookURLNotAllowed(f"Could not resolve webhook host: {host}")
    for ip in ips:
        if not _is_public_ip(ip):
            raise WebhookURLNotAllowed(f"Webhook host resolves to a non-public address ({ip})")

# Canonical severity ordering. Higher rank = more severe.
SEVERITY_ORDER = {"info": 0, "warning": 1, "high": 2, "critical": 3}

WEBHOOK_TIMEOUT_SECONDS = 10


def severity_rank(name: str | None) -> int:
    """Rank a severity label. Unknown/empty labels rank as the lowest (info)."""
    return SEVERITY_ORDER.get((name or "").strip().lower(), 0)


def _frontend_url() -> str:
    raw = os.getenv("FRONTEND_URL", "http://localhost:3000")
    # FRONTEND_URL may be a comma-separated allowlist; use the first entry.
    return raw.split(",")[0].strip().rstrip("/")


def _scan_link(alert: Alert) -> str | None:
    if not alert.scan_id:
        return None
    return f"{_frontend_url()}/scan/{alert.scan_id}"


def deliver_alert(db: Session, alert: Alert) -> None:
    """Deliver *alert* to the owner's enabled channels, honouring their threshold."""
    settings = (
        db.query(NotificationSettings)
        .filter(NotificationSettings.owner_email == alert.owner_email)
        .first()
    )
    if settings is None:
        return
    if severity_rank(alert.severity) < severity_rank(settings.min_severity):
        return

    if settings.email_enabled:
        _safe("email", send_email, settings, alert)
    if settings.webhook_enabled and settings.webhook_url:
        _safe("webhook", send_webhook, settings, alert)


def _safe(channel: str, fn, settings: NotificationSettings, alert: Alert) -> None:
    try:
        fn(settings, alert)
    except Exception:
        logger.exception("notifications: %s delivery failed for alert=%s", channel, alert.id)


def send_email(settings: NotificationSettings, alert: Alert) -> None:
    """Send an alert email via the server-configured SMTP transport.

    Skips (logs) rather than errors when SMTP is not configured, so a missing
    transport never surfaces as a delivery exception.
    """
    host = os.getenv("SMTP_HOST")
    if not host:
        logger.info("notifications: SMTP_HOST unset; skipping email for alert=%s", alert.id)
        return

    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM", username or "easm@localhost")
    use_starttls = os.getenv("SMTP_STARTTLS", "true").strip().lower() not in ("0", "false", "no")
    recipient = settings.email_address or settings.owner_email

    message = EmailMessage()
    message["Subject"] = f"[EASM] {alert.severity} change on {alert.target}"
    message["From"] = sender
    message["To"] = recipient
    link = _scan_link(alert)
    body = alert.message
    if link:
        body += f"\n\nView scan: {link}"
    message.set_content(body)

    with smtplib.SMTP(host, port, timeout=WEBHOOK_TIMEOUT_SECONDS) as server:
        if use_starttls:
            server.starttls()
        if username and password:
            server.login(username, password)
        server.send_message(message)
    logger.info("notifications: emailed alert=%s to %s", alert.id, recipient)


def send_webhook(settings: NotificationSettings, alert: Alert) -> None:
    """POST a JSON representation of the alert to the user's webhook URL."""
    validate_webhook_url(settings.webhook_url)  # SSRF guard — checked at send time
    payload = {
        "target": alert.target,
        "severity": alert.severity,
        "type": alert.type,
        "message": alert.message,
        "scan_id": alert.scan_id,
        "created_at": alert.created_at.isoformat() if alert.created_at else None,
        "url": _scan_link(alert),
    }
    response = httpx.post(settings.webhook_url, json=payload, timeout=WEBHOOK_TIMEOUT_SECONDS)
    response.raise_for_status()
    logger.info("notifications: posted alert=%s to webhook", alert.id)
