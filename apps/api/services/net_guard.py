"""
net_guard.py
------------
Shared network/SSRF guards.

Two concerns live here so the rules can't drift between callers:

* IP/host classification (``is_public_ip`` / ``is_public_host``) — also reused
  by the webhook delivery guard in :mod:`services.notifications`.
* Scan-target cleaning + policy (``clean_target`` / ``validate_scan_target``) —
  reused by the one-off scan and recurring-schedule routers.

A scan target that resolves to a loopback, RFC-1918, link-local (e.g. the
``169.254.169.254`` cloud-metadata endpoint), or otherwise non-public address
is rejected by default, so a user cannot turn the scanner into an SSRF probe of
internal infrastructure. Operators who genuinely need to scan internal ranges
opt in with ``ALLOW_PRIVATE_TARGETS=true``.
"""

import ipaddress
import os
import re
import socket

VALID_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9.-]+$")


class TargetNotAllowed(ValueError):
    """Raised when a target is well-formed but disallowed by policy (SSRF)."""


def resolve_ips(host: str) -> list[str]:
    """Resolve a hostname to its IP addresses (empty list on failure)."""
    try:
        return [info[4][0] for info in socket.getaddrinfo(host, None)]
    except (socket.gaierror, UnicodeError):
        return []


def is_public_ip(ip_str: str) -> bool:
    """True only for globally-routable, non-internal addresses."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def is_public_host(host: str) -> bool:
    """True if *host* is public.

    A literal IP is classified directly. A hostname is resolved; it is public
    only when it resolves to at least one address and *every* resolved address
    is public (a single internal record blocks it). An unresolvable hostname is
    treated as public — scanning it cannot reach an internal host anyway.
    """
    try:
        ipaddress.ip_address(host)
        return is_public_ip(host)  # literal IP — no DNS
    except ValueError:
        pass
    ips = resolve_ips(host)
    if not ips:
        return True
    return all(is_public_ip(ip) for ip in ips)


def private_targets_allowed() -> bool:
    """Whether the operator has opted in to scanning private/internal targets."""
    return os.getenv("ALLOW_PRIVATE_TARGETS", "false").strip().lower() in ("1", "true", "yes")


def clean_target(raw_target: str) -> str:
    """Normalise a user-supplied target to a bare host, validating its format.

    Strips an optional scheme, path, port, and leading ``www.``; lower-cases the
    result. Raises ``ValueError`` if the target is empty or not a plausible
    hostname/IP. (Does not apply the public/private SSRF policy — see
    :func:`validate_scan_target`.)
    """
    from urllib.parse import urlparse

    if not raw_target or not raw_target.strip():
        raise ValueError("Target is required")

    target = raw_target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path

    target = target.split("/", 1)[0].strip().lower()
    target = target.split(":", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if not target or " " in target:
        raise ValueError("Invalid target format")
    if not VALID_TARGET_PATTERN.fullmatch(target):
        raise ValueError("Invalid target format")
    if "." not in target and not target.replace(".", "").isdigit():
        raise ValueError("Invalid target format")
    return target


def validate_scan_target(raw_target: str) -> str:
    """Clean *raw_target* and enforce the SSRF policy. Returns the clean host.

    Raises ``ValueError`` (``TargetNotAllowed``) if the target resolves to a
    non-public address and ``ALLOW_PRIVATE_TARGETS`` is not set.
    """
    target = clean_target(raw_target)
    if not private_targets_allowed() and not is_public_host(target):
        raise TargetNotAllowed(
            "Target resolves to a private or internal address and is not allowed. "
            "Set ALLOW_PRIVATE_TARGETS=true on the server to scan internal hosts."
        )
    return target
