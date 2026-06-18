"""
http_common.py
--------------
Shared HTTP helpers for the active web modules (web_audit, web_vuln_probe):
base-URL derivation from discovered ports and a guarded GET. Keeping these in
one place avoids duplicating the logic across modules.
"""

import logging
from typing import Iterable, Optional

import httpx

try:
    from .models import PortResult
except ImportError:  # pragma: no cover
    from models import PortResult

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 8
USER_AGENT = "Mozilla/5.0 (compatible; EASM-Scanner/1.0)"
HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000]


def base_urls(host: str, ports: Iterable[PortResult]) -> list[str]:
    """Derive scheme://host:port base URLs for the HTTP services among `ports`."""
    seen: set[tuple[str, int]] = set()
    urls: list[str] = []
    for port in ports or []:
        service = (port.service or "").lower()
        is_http = service in {"http", "https", "http-alt", "ssl"} or port.port in HTTP_PORTS
        if not is_http:
            continue
        use_tls = port.port in (443, 8443) or "ssl" in service or "https" in service
        scheme = "https" if use_tls else "http"
        key = (scheme, port.port)
        if key in seen:
            continue
        seen.add(key)
        urls.append(f"{scheme}://{host}:{port.port}")
    return urls


def get(
    client: httpx.Client,
    url: str,
    headers: Optional[dict[str, str]] = None,
    timeout: float = HTTP_TIMEOUT,
) -> Optional[httpx.Response]:
    """GET `url` without following redirects, swallowing transport errors."""
    try:
        return client.get(url, headers=headers, timeout=timeout, follow_redirects=False)
    except (httpx.RequestError, OSError) as exc:
        logger.debug("http_common: GET failed for %s: %s", url, exc)
        return None
