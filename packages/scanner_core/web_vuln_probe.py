"""
web_vuln_probe.py
-----------------
Active (non-destructive) web vulnerability probe. Where web_audit looks for
misconfigurations/exposures, this module shallow-crawls discovered HTTP services
to find injectable inputs (query params, form fields) and tests each for:

  - Error-based SQL injection   (DB error signatures, baseline-diffed)
  - Reflected XSS               (raw, un-escaped marker reflection)
  - Path traversal / LFI        (/etc/passwd & win.ini signatures)
  - Open redirect               (attacker host in Location header of a 3xx)
  - OS command injection        (arithmetic result echoed -> proves execution)

All payloads are non-destructive. Hard page/request caps plus a wall-clock
deadline keep the module well inside the scan budget. It never raises to the
worker. Shared HTTP helpers come from http_common.
"""

import logging
import re
from typing import Optional

try:
    from .models import Finding
except ImportError:  # pragma: no cover
    from models import Finding

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 6
MAX_BASE_URLS = 2
MAX_PAGES_CRAWLED = 10
MAX_INJECTION_POINTS = 15
MAX_PARAMS_PER_POINT = 5
MODULE_DEADLINE_SECONDS = 45

SQL_ERROR_RE = re.compile(
    "|".join([
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"mysql_fetch",
        r"supplied argument is not a valid mysql",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"pg::\w*error",
        r"pg_query\(\)",
        r"sqlite3?::",
        r"sqlite_error",
        r"ora-\d{5}",
        r"odbc sql server driver",
    ]),
    re.IGNORECASE,
)

LFI_RE = re.compile(
    "|".join([r"root:.*:0:0:", r"\[boot loader\]", r"\[fonts\]", r"\[extensions\]"]),
    re.IGNORECASE,
)

# 13337 * 31337 == 418142369. The literal payload never contains the product,
# so plain reflection of the payload cannot produce a false positive.
CMD_MARKER = "418142369"

XSS_MARKER = "easmx9z1"
XSS_PAYLOAD = f'{XSS_MARKER}"><svg/onload=alert(1)>'
SQLI_PAYLOADS = ["'", "' OR '1'='1"]
LFI_PAYLOADS = ["../../../../../../etc/passwd", "....//....//....//....//etc/passwd"]
OPEN_REDIRECT_PAYLOAD = "https://evil.example/"
CMD_PAYLOADS = [";echo $((13337*31337))", "| echo $((13337*31337))"]


def _detect_sqli(baseline_body: str, injected_body: str) -> bool:
    return bool(SQL_ERROR_RE.search(injected_body or "")) and not SQL_ERROR_RE.search(baseline_body or "")


def _detect_xss(injected_body: str, payload: str) -> bool:
    return payload in (injected_body or "")


def _detect_lfi(injected_body: str) -> bool:
    return bool(LFI_RE.search(injected_body or ""))


def _detect_open_redirect(location: Optional[str]) -> bool:
    return bool(location) and "evil.example" in location.lower()


def _detect_cmd_injection(injected_body: str) -> bool:
    return CMD_MARKER in (injected_body or "")
