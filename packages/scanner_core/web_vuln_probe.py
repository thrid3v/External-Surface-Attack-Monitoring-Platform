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
    from .models import Finding, PortResult
except ImportError:  # pragma: no cover
    from models import Finding, PortResult

try:
    from .http_common import USER_AGENT, base_urls, get
except ImportError:  # pragma: no cover
    from http_common import USER_AGENT, base_urls, get

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


def _finding(title: str, severity: str, target: str, evidence: str, remediation: str) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category="web_vuln",
        description=f"{title} detected via active parameter testing.",
        target=target,
        evidence=evidence,
        remediation=remediation,
        source="web_vuln_probe",
    )


def _request(client: httpx.Client, url: str, method: str, params: dict[str, str]) -> Optional[httpx.Response]:
    try:
        if method == "POST":
            return client.post(url, data=params, timeout=HTTP_TIMEOUT, follow_redirects=False)
        return client.get(url, params=params, timeout=HTTP_TIMEOUT, follow_redirects=False)
    except (httpx.RequestError, OSError) as exc:
        logger.debug("web_vuln_probe: %s %s failed: %s", method, url, exc)
        return None


def _mutate(params: dict[str, str], name: str, value: str) -> dict[str, str]:
    out = dict(params)
    out[name] = value
    return out


def _probe_point(client: httpx.Client, point: InjectionPoint, budget: _Budget) -> list[Finding]:
    findings: list[Finding] = []
    names = list(point.params)[:MAX_PARAMS_PER_POINT]

    baseline = _request(client, point.url, point.method, point.params)
    baseline_body = (baseline.text if baseline is not None else "") or ""

    for name in names:
        if budget.expired():
            break
        base_val = point.params.get(name) or ""
        target_desc = f"{point.url} [{point.method} param: {name}]"

        # SQLi (append metacharacter to the baseline value)
        for payload in SQLI_PAYLOADS:
            resp = _request(client, point.url, point.method, _mutate(point.params, name, base_val + payload))
            if resp is not None and _detect_sqli(baseline_body, resp.text or ""):
                findings.append(_finding(
                    "SQL injection (error-based)", "HIGH", target_desc,
                    f"DB error triggered by payload {payload!r} in '{name}'",
                    "Use parameterised queries / prepared statements; never concatenate input into SQL.",
                ))
                break

        # Reflected XSS
        resp = _request(client, point.url, point.method, _mutate(point.params, name, XSS_PAYLOAD))
        if resp is not None and _detect_xss(resp.text or "", XSS_PAYLOAD):
            findings.append(_finding(
                "Reflected XSS", "MEDIUM", target_desc,
                f"Un-escaped marker reflected from '{name}'",
                "Context-encode all user input on output; apply a strict Content-Security-Policy.",
            ))

        # Path traversal / LFI
        for payload in LFI_PAYLOADS:
            resp = _request(client, point.url, point.method, _mutate(point.params, name, payload))
            if resp is not None and _detect_lfi(resp.text or ""):
                findings.append(_finding(
                    "Path traversal / LFI", "HIGH", target_desc,
                    f"System file signature returned for payload {payload!r} in '{name}'",
                    "Reject path separators; resolve and confine paths to an allowlisted directory.",
                ))
                break

        # Open redirect
        resp = _request(client, point.url, point.method, _mutate(point.params, name, OPEN_REDIRECT_PAYLOAD))
        if resp is not None and 300 <= resp.status_code < 400 and _detect_open_redirect(resp.headers.get("location")):
            findings.append(_finding(
                "Open redirect", "MEDIUM", target_desc,
                f"Location header points to attacker host via '{name}'",
                "Validate redirect targets against an allowlist of internal paths/hosts.",
            ))

        # OS command injection
        for payload in CMD_PAYLOADS:
            resp = _request(client, point.url, point.method, _mutate(point.params, name, base_val + payload))
            if resp is not None and _detect_cmd_injection(resp.text or ""):
                findings.append(_finding(
                    "OS command injection", "CRITICAL", target_desc,
                    f"Arithmetic command result ({CMD_MARKER}) echoed for payload in '{name}'",
                    "Never pass user input to a shell; use argument arrays and strict input validation.",
                ))
                break

    return findings


def probe_web_vulns(host: str, ports: Iterable[PortResult]) -> list[Finding]:
    """Actively probe the host's HTTP services for injection-class vulnerabilities."""
    bases = base_urls(host, list(ports))[:MAX_BASE_URLS]
    if not bases:
        return []
    budget = _Budget(deadline=time.monotonic() + MODULE_DEADLINE_SECONDS, pages_left=MAX_PAGES_CRAWLED)
    collected: list[Finding] = []
    with httpx.Client(verify=False, headers={"User-Agent": USER_AGENT}, follow_redirects=False) as client:
        try:
            points = _discover_inputs(client, bases, budget)
            for point in points:
                if budget.expired():
                    break
                collected.extend(_probe_point(client, point, budget))
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("web_vuln_probe: probe failed for %s: %s", host, exc)

    deduped: dict[tuple[str, Optional[str]], Finding] = {}
    for f in collected:
        deduped[(f.title, f.target)] = f
    result = list(deduped.values())
    logger.info("web_vuln_probe: %d findings for %s", len(result), host)
    return result
