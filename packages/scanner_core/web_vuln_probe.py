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
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx

try:
    from .models import Finding
except ImportError:  # pragma: no cover
    from models import Finding

try:
    from .http_common import get
except ImportError:  # pragma: no cover
    from http_common import get

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


class _InputExtractor(HTMLParser):
    """Collect anchor hrefs and form definitions from an HTML document."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: Optional[dict] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "fields": {},
            }
            self.forms.append(self._current_form)
        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = a.get("name")
            if name:
                self._current_form["fields"][name] = a.get("value") or "test"

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        # void elements like <input/> dispatch here; reuse the same logic.
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


@dataclass
class InjectionPoint:
    url: str                # URL without query (GET) or form action (POST)
    method: str             # "GET" | "POST"
    params: dict[str, str]  # param name -> baseline value


@dataclass
class _Budget:
    deadline: float
    pages_left: int

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline


def _discover_inputs(client: httpx.Client, bases: list[str], budget: _Budget) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()

    def _add(url: str, method: str, params: dict[str, str]) -> None:
        if not params or len(points) >= MAX_INJECTION_POINTS:
            return
        key = (url, method, tuple(sorted(params)))
        if key in seen:
            return
        seen.add(key)
        points.append(InjectionPoint(url=url, method=method, params=params))

    for base in bases:
        host = urlparse(base).netloc
        to_visit = [base]
        visited: set[str] = set()
        while (
            to_visit
            and budget.pages_left > 0
            and not budget.expired()
            and len(points) < MAX_INJECTION_POINTS
        ):
            current = to_visit.pop(0)
            if current in visited:
                continue
            visited.add(current)
            budget.pages_left -= 1
            resp = get(client, current, timeout=HTTP_TIMEOUT)
            if resp is None:
                continue

            cur_parsed = urlparse(current)
            cur_query = dict(parse_qsl(cur_parsed.query))
            if cur_query:
                _add(current.split("?")[0], "GET", cur_query)

            extractor = _InputExtractor()
            try:
                extractor.feed(resp.text or "")
            except Exception:  # pragma: no cover - defensive
                continue

            for href in extractor.links:
                absolute = urljoin(current, href).split("#")[0]
                parsed = urlparse(absolute)
                if parsed.netloc != host:
                    continue
                if parsed.query:
                    _add(absolute.split("?")[0], "GET", dict(parse_qsl(parsed.query)))
                if absolute not in visited and absolute not in to_visit and len(to_visit) < MAX_PAGES_CRAWLED:
                    to_visit.append(absolute)

            for form in extractor.forms:
                action = urljoin(current, form["action"]) if form["action"] else current
                if urlparse(action).netloc != host:
                    continue
                method = "POST" if form["method"] == "post" else "GET"
                if form["fields"]:
                    _add(action.split("?")[0], method, dict(form["fields"]))
    return points
