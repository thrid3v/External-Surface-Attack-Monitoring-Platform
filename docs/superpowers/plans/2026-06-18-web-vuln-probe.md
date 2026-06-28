# Active Web Vulnerability Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `web_vuln_probe` scanner module that actively (non-destructively) tests discovered HTTP inputs for reflected XSS, error-based SQLi, path traversal/LFI, open redirect, and OS command injection, producing `Finding`s that raise risk-score fidelity on application targets.

**Architecture:** A shared `scanner_core/http_common.py` holds HTTP-base-URL derivation and a guarded GET (extracted from `web_audit` so the two modules don't duplicate it). The new module `packages/scanner_core/web_vuln_probe.py` uses those helpers to shallow-crawl HTTP services with a stdlib `HTMLParser`, finding injectable query params and form fields, then injects a small payload set per class and detects via signatures (with baseline diffing for FP reduction). Hard request/page caps plus a 45s wall-clock deadline keep it inside the scan budget. It is wired into `MODULE_ORDER` after `web_audit`.

**Tech Stack:** Python, `httpx` (already a dependency), stdlib `html.parser`/`urllib.parse`/`re`, Pydantic `Finding` model. Tests use `pytest` + `respx` (already present).

## Global Constraints

- No new runtime dependencies — only `httpx` + Python stdlib.
- Shared HTTP helpers live in `scanner_core/http_common.py`; `web_audit` and `web_vuln_probe` both import from it rather than each defining their own `base_urls`/`get`/HTTP constants.
- All `Finding`s produced by the probe MUST use `category="web_vuln"` and `source="web_vuln_probe"`.
- `Finding` model fields (from `scanner_core.models`): `title` (str), `severity` (CRITICAL|HIGH|MEDIUM|LOW|INFO), `category` (str), `description` (str), `target` (Optional[str]), `evidence` (Optional[str]), `remediation` (Optional[str]), `source` (str), `references` (list[str]).
- Payloads MUST be non-destructive: no `DROP`/`DELETE`, no `rm`, no `sleep`-based DoS.
- Budgets are fixed (conservative): `MAX_PAGES_CRAWLED=10`, `MAX_INJECTION_POINTS=15`, `MAX_PARAMS_PER_POINT=5`, probe `HTTP_TIMEOUT=6`, `MODULE_DEADLINE_SECONDS=45`. (Shared `http_common.HTTP_TIMEOUT=8` is web_audit's default; the probe passes its own 6s.)
- The probe module MUST NOT raise out to the worker — all network/parse errors are caught and logged.
- Tests run with: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/ -v` (run from repo root `C:\PROJECTS\easm`).
- Commits: follow repo convention (`feat(scanner): ...`), NO `Co-Authored-By` trailer.

---

### Task 1: Shared HTTP helper + web_audit refactor

**Files:**
- Create: `packages/scanner_core/http_common.py`
- Modify: `packages/scanner_core/web_audit.py` (remove local copies, import shared helpers)
- Test: `packages/scanner_core/tests/test_http_common.py` (new)
- Test: `packages/scanner_core/tests/test_web_audit.py` (new — regression guard for the refactor)

**Interfaces:**
- Consumes: `scanner_core.models.PortResult`.
- Produces:
  - `http_common.USER_AGENT: str`, `http_common.HTTP_PORTS: list[int]`, `http_common.HTTP_TIMEOUT: int` (=8)
  - `http_common.base_urls(host: str, ports: Iterable[PortResult]) -> list[str]`
  - `http_common.get(client: httpx.Client, url: str, headers: Optional[dict[str,str]] = None, timeout: float = HTTP_TIMEOUT) -> Optional[httpx.Response]`

- [ ] **Step 1: Write the failing tests**

```python
# packages/scanner_core/tests/test_http_common.py
import httpx
import respx

from scanner_core import http_common
from scanner_core.models import PortResult


def test_base_urls_derives_http_endpoints_and_skips_non_http():
    ports = [
        PortResult(port=80, protocol="tcp", state="open", service="http"),
        PortResult(port=443, protocol="tcp", state="open", service="https"),
        PortResult(port=22, protocol="tcp", state="open", service="ssh"),
    ]
    bases = http_common.base_urls("example.com", ports)
    assert "http://example.com:80" in bases
    assert "https://example.com:443" in bases
    assert all(":22" not in b for b in bases)


@respx.mock
def test_get_returns_none_on_transport_error():
    respx.get("http://down.test/").mock(side_effect=httpx.ConnectError("boom"))
    with httpx.Client() as client:
        assert http_common.get(client, "http://down.test/") is None
```

```python
# packages/scanner_core/tests/test_web_audit.py
import httpx
import respx

from scanner_core.models import PortResult
from scanner_core.web_audit import audit_web


@respx.mock
def test_audit_web_flags_directory_listing_after_refactor():
    respx.get("http://h.test:80/").mock(
        return_value=httpx.Response(200, text="<title>Index of /</title>")
    )
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="nope"))
    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    findings = audit_web("h.test", ports)
    assert any(f.title == "Directory listing enabled" for f in findings)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_http_common.py packages/scanner_core/tests/test_web_audit.py -v`
Expected: `test_http_common.py` FAILs with `ModuleNotFoundError: scanner_core.http_common`. `test_web_audit.py` may already PASS (web_audit currently works) — that is fine; it is the regression guard for Step 3/4.

- [ ] **Step 3: Create the shared helper**

```python
# packages/scanner_core/http_common.py
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
```

- [ ] **Step 4: Refactor `web_audit.py` onto the shared helper**

In `packages/scanner_core/web_audit.py`:

1. Replace the local constants block. Change:
   ```python
   HTTP_TIMEOUT = 8
   USER_AGENT = "Mozilla/5.0 (compatible; EASM-Scanner/1.0)"
   HTTP_PORTS = [80, 443, 8080, 8443, 8000, 3000]
   MAX_BASE_URLS = 2  # bound path probing across services
   ```
   to:
   ```python
   from .http_common import USER_AGENT, base_urls, get
   MAX_BASE_URLS = 2  # bound path probing across services
   ```
   (Place the `from .http_common import ...` near the existing `try/except` models import; keep `MAX_BASE_URLS` as a module constant. `HTTP_TIMEOUT` and `HTTP_PORTS` are no longer referenced in this file once the local `_base_urls`/`_get` are removed.)

2. Delete the local `_base_urls(host, ports)` function (the whole `def _base_urls(...)` block).

3. Delete the local `_get(client, url, headers=None)` function (the whole `def _get(...)` block).

4. Replace call sites:
   - In `_check_paths`: `resp = _get(client, base + path)` → `resp = get(client, base + path)`
   - In `_check_root`: `resp = _get(client, base + "/")` → `resp = get(client, base + "/")`
   - In `_check_root`: `cors = _get(client, base + "/", headers={"Origin": "https://evil.example"})` → `cors = get(client, base + "/", headers={"Origin": "https://evil.example"})`
   - In `audit_web`: `bases = _base_urls(host, list(ports))[:MAX_BASE_URLS]` → `bases = base_urls(host, list(ports))[:MAX_BASE_URLS]`

   (`USER_AGENT` is still referenced in `audit_web`'s `httpx.Client(... headers={"User-Agent": USER_AGENT})` and now comes from the import.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_http_common.py packages/scanner_core/tests/test_web_audit.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add packages/scanner_core/http_common.py packages/scanner_core/web_audit.py packages/scanner_core/tests/test_http_common.py packages/scanner_core/tests/test_web_audit.py
git commit -m "refactor(scanner): extract shared http_common helper from web_audit"
```

---

### Task 2: Probe detectors, signatures, and payloads

**Files:**
- Create: `packages/scanner_core/web_vuln_probe.py`
- Test: `packages/scanner_core/tests/test_web_vuln_probe.py`

**Interfaces:**
- Consumes: `scanner_core.models.Finding`.
- Produces:
  - Constants: `HTTP_TIMEOUT=6`, `MAX_BASE_URLS=2`, `MAX_PAGES_CRAWLED=10`, `MAX_INJECTION_POINTS=15`, `MAX_PARAMS_PER_POINT=5`, `MODULE_DEADLINE_SECONDS=45`
  - `SQL_ERROR_RE`, `LFI_RE` (compiled regexes); `XSS_PAYLOAD: str`, `CMD_MARKER: str`, `SQLI_PAYLOADS`, `LFI_PAYLOADS`, `OPEN_REDIRECT_PAYLOAD`, `CMD_PAYLOADS`
  - `_detect_sqli(baseline_body: str, injected_body: str) -> bool`
  - `_detect_xss(injected_body: str, payload: str) -> bool`
  - `_detect_lfi(injected_body: str) -> bool`
  - `_detect_open_redirect(location: Optional[str]) -> bool`
  - `_detect_cmd_injection(injected_body: str) -> bool`

- [ ] **Step 1: Write the failing test**

```python
# packages/scanner_core/tests/test_web_vuln_probe.py
from scanner_core import web_vuln_probe as wvp


def test_detect_sqli_only_when_error_is_new():
    err = "You have an error in your SQL syntax near ''' at line 1"
    assert wvp._detect_sqli(baseline_body="welcome", injected_body=err) is True
    # FP guard: error already present in baseline -> not a finding
    assert wvp._detect_sqli(baseline_body=err, injected_body=err) is False


def test_detect_xss_requires_raw_unescaped_marker():
    assert wvp._detect_xss(f"<div>{wvp.XSS_PAYLOAD}</div>", wvp.XSS_PAYLOAD) is True
    escaped = wvp.XSS_PAYLOAD.replace("<", "&lt;").replace(">", "&gt;")
    assert wvp._detect_xss(f"<div>{escaped}</div>", wvp.XSS_PAYLOAD) is False


def test_detect_lfi_matches_passwd_signature():
    assert wvp._detect_lfi("root:x:0:0:root:/root:/bin/bash\n") is True
    assert wvp._detect_lfi("nothing interesting here") is False


def test_detect_open_redirect_only_from_location_header():
    assert wvp._detect_open_redirect("https://evil.example/") is True
    assert wvp._detect_open_redirect(None) is False
    assert wvp._detect_open_redirect("/local/path") is False


def test_detect_cmd_injection_uses_arithmetic_result():
    # The product proves execution; the literal payload never contains it.
    assert wvp.CMD_MARKER not in ";echo $((13337*31337))"
    assert wvp._detect_cmd_injection(f"output: {wvp.CMD_MARKER}") is True
    assert wvp._detect_cmd_injection("output: 13337*31337") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_web_vuln_probe.py -v`
Expected: FAIL — `ModuleNotFoundError`/`AttributeError` (module/attrs not defined).

- [ ] **Step 3: Write minimal implementation**

```python
# packages/scanner_core/web_vuln_probe.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_web_vuln_probe.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/scanner_core/web_vuln_probe.py packages/scanner_core/tests/test_web_vuln_probe.py
git commit -m "feat(scanner): add web_vuln_probe detectors and payloads"
```

---

### Task 3: HTML input extractor

**Files:**
- Modify: `packages/scanner_core/web_vuln_probe.py`
- Test: `packages/scanner_core/tests/test_web_vuln_probe.py`

**Interfaces:**
- Consumes: nothing from prior tasks (extends the same module).
- Produces: `_InputExtractor(HTMLParser)` with attributes `links: list[str]` and `forms: list[dict]` where each form is `{"action": str, "method": str, "fields": dict[str, str]}`.

- [ ] **Step 1: Write the failing test**

```python
# append to packages/scanner_core/tests/test_web_vuln_probe.py
def test_input_extractor_collects_links_and_forms():
    html = """
    <html><body>
      <a href="/products.php?cat=1">cat</a>
      <a href="/about">about</a>
      <form action="/search.php" method="post">
        <input name="q" value="x">
        <textarea name="note"></textarea>
        <input name="csrf" type="hidden" value="tok">
      </form>
    </body></html>
    """
    ex = wvp._InputExtractor()
    ex.feed(html)
    assert "/products.php?cat=1" in ex.links
    assert "/about" in ex.links
    assert len(ex.forms) == 1
    form = ex.forms[0]
    assert form["action"] == "/search.php"
    assert form["method"] == "post"
    assert set(form["fields"]) == {"q", "note", "csrf"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_web_vuln_probe.py::test_input_extractor_collects_links_and_forms -v`
Expected: FAIL — `AttributeError: module ... has no attribute '_InputExtractor'`.

- [ ] **Step 3: Write minimal implementation**

Add the import at the top of `web_vuln_probe.py` (with the other stdlib imports):

```python
from html.parser import HTMLParser
```

Then add the class (after the detector functions):

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_web_vuln_probe.py::test_input_extractor_collects_links_and_forms -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/scanner_core/web_vuln_probe.py packages/scanner_core/tests/test_web_vuln_probe.py
git commit -m "feat(scanner): add HTML input extractor for web_vuln_probe"
```

---

### Task 4: Budget and injection-point discovery

**Files:**
- Modify: `packages/scanner_core/web_vuln_probe.py`
- Test: `packages/scanner_core/tests/test_web_vuln_probe.py`

**Interfaces:**
- Consumes: `_InputExtractor` (Task 3); `MAX_*` constants (Task 2); `http_common.get` (Task 1).
- Produces:
  - `@dataclass InjectionPoint(url: str, method: str, params: dict[str, str])`
  - `@dataclass _Budget(deadline: float, pages_left: int)` with `expired() -> bool`
  - `_discover_inputs(client: httpx.Client, bases: list[str], budget: _Budget) -> list[InjectionPoint]`

- [ ] **Step 1: Write the failing test**

```python
# append to packages/scanner_core/tests/test_web_vuln_probe.py
import time

import httpx
import respx


def _budget():
    return wvp._Budget(deadline=time.monotonic() + 30, pages_left=wvp.MAX_PAGES_CRAWLED)


@respx.mock
def test_discover_inputs_finds_query_links_and_forms_same_host_only():
    root = """
    <a href="/list.php?cat=1">x</a>
    <a href="https://other.test/evil?z=1">offsite</a>
    <form action="/search.php" method="post"><input name="q"></form>
    """
    respx.get("http://t.test:80").mock(return_value=httpx.Response(200, text=root))
    respx.get(url__regex=r"http://t\.test:80/.*").mock(return_value=httpx.Response(200, text="ok"))

    with httpx.Client() as client:
        points = wvp._discover_inputs(client, ["http://t.test:80"], _budget())

    urls = {(p.method, p.url) for p in points}
    assert ("GET", "http://t.test:80/list.php") in urls
    assert ("POST", "http://t.test:80/search.php") in urls
    # off-host link must not become an injection point
    assert all("other.test" not in p.url for p in points)


@respx.mock
def test_discover_inputs_respects_page_budget():
    # Every page links to a fresh unvisited page; with pages_left=1 only the
    # first page is fetched, so its links are discovered but none are crawled.
    respx.get(url__regex=r".*").mock(
        return_value=httpx.Response(200, text='<a href="/next.php?p=1">n</a>')
    )
    budget = wvp._Budget(deadline=time.monotonic() + 30, pages_left=1)
    with httpx.Client() as client:
        wvp._discover_inputs(client, ["http://b.test:80"], budget)
    assert budget.pages_left == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_web_vuln_probe.py -k "discover_inputs" -v`
Expected: FAIL — `AttributeError` (`_Budget`/`_discover_inputs` not defined).

- [ ] **Step 3: Write minimal implementation**

Add these imports at the top of `web_vuln_probe.py` (extend the existing import block):

```python
import time
from dataclasses import dataclass
from typing import Iterable, Optional   # extend existing "from typing import Optional"
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx

from .http_common import get   # alongside the models import; mirror the try/except if needed
```

> Note: `web_vuln_probe` lives in the same package as `http_common`, so `from .http_common import get` works under the normal import path. Keep the existing `try/except` models import pattern; the `http_common` import can sit directly below it.

Then add (after `_InputExtractor`):

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_web_vuln_probe.py -k "discover_inputs" -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/scanner_core/web_vuln_probe.py packages/scanner_core/tests/test_web_vuln_probe.py
git commit -m "feat(scanner): add bounded injection-point discovery to web_vuln_probe"
```

---

### Task 5: Probing engine and public entrypoint

**Files:**
- Modify: `packages/scanner_core/web_vuln_probe.py`
- Test: `packages/scanner_core/tests/test_web_vuln_probe.py`

**Interfaces:**
- Consumes: `InjectionPoint`, `_Budget`, `_discover_inputs` (Task 4); all detectors/payloads (Task 2); `http_common.base_urls` and `http_common.USER_AGENT` (Task 1).
- Produces:
  - `_finding(title, severity, target, evidence, remediation) -> Finding`
  - `_request(client, url, method, params) -> Optional[httpx.Response]`
  - `_mutate(params: dict[str,str], name: str, value: str) -> dict[str,str]`
  - `_probe_point(client, point: InjectionPoint, budget: _Budget) -> list[Finding]`
  - `probe_web_vulns(host: str, ports: Iterable[PortResult]) -> list[Finding]`

- [ ] **Step 1: Write the failing test**

```python
# append to packages/scanner_core/tests/test_web_vuln_probe.py
@respx.mock
def test_probe_web_vulns_flags_sqli():
    from scanner_core.models import PortResult

    MYSQL_ERR = "You have an error in your SQL syntax; check the manual"

    def vuln_handler(request):
        # SQL error only when a single quote is present in the cat param.
        if "'" in request.url.params.get("cat", ""):
            return httpx.Response(200, text=MYSQL_ERR)
        return httpx.Response(200, text="<html>products</html>")

    root_html = '<a href="/list.php?cat=1">items</a>'
    respx.get("http://v.test:80").mock(return_value=httpx.Response(200, text=root_html))
    respx.get("http://v.test:80/list.php").mock(side_effect=vuln_handler)

    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    findings = wvp.probe_web_vulns("v.test", ports)

    sqli = [f for f in findings if f.title.lower().startswith("sql")]
    assert sqli, f"expected a SQLi finding, got {[f.title for f in findings]}"
    assert sqli[0].severity == "HIGH"
    assert sqli[0].category == "web_vuln"
    assert sqli[0].source == "web_vuln_probe"


@respx.mock
def test_probe_web_vulns_clean_target_has_no_findings():
    from scanner_core.models import PortResult
    respx.get("http://safe.test:80").mock(
        return_value=httpx.Response(200, text='<a href="/p.php?id=1">x</a>')
    )
    respx.get("http://safe.test:80/p.php").mock(return_value=httpx.Response(200, text="all good"))
    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    assert wvp.probe_web_vulns("safe.test", ports) == []


def test_probe_web_vulns_returns_empty_without_http_ports():
    from scanner_core.models import PortResult
    ports = [PortResult(port=22, protocol="tcp", state="open", service="ssh")]
    assert wvp.probe_web_vulns("nohttp.test", ports) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_web_vuln_probe.py -k "probe_web_vulns" -v`
Expected: FAIL — `AttributeError: ... 'probe_web_vulns'`.

- [ ] **Step 3: Write minimal implementation**

Extend the `http_common` import at the top of `web_vuln_probe.py` to also bring in `base_urls` and `USER_AGENT`:

```python
from .http_common import USER_AGENT, base_urls, get
```

Then add (after `_discover_inputs`):

```python
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
        if resp is not None and _detect_open_redirect(resp.headers.get("location")):
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
```

> The `PortResult` type used in the `probe_web_vulns` signature is already available via the `from .models import Finding` block — extend that import to `from .models import Finding, PortResult` (and the `except ImportError` fallback to `from models import Finding, PortResult`).

- [ ] **Step 4: Run the full module test suite to verify it passes**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_web_vuln_probe.py -v`
Expected: PASS (all tests, including the three new probe tests).

- [ ] **Step 5: Commit**

```bash
git add packages/scanner_core/web_vuln_probe.py packages/scanner_core/tests/test_web_vuln_probe.py
git commit -m "feat(scanner): add probing engine and probe_web_vulns entrypoint"
```

---

### Task 6: Wire `web_vuln_probe` into the scan pipeline

**Files:**
- Modify: `apps/api/constants.py` (the `MODULE_ORDER` list)
- Modify: `apps/api/workers/scan_worker.py` (import + guarded module block)

**Interfaces:**
- Consumes: `probe_web_vulns` (Task 5).
- Produces: `"web_vuln_probe"` present in `MODULE_ORDER`; worker executes it after `web_audit`.

- [ ] **Step 1: Add the module to `MODULE_ORDER`**

In `apps/api/constants.py`, change the `MODULE_ORDER` list to insert `"web_vuln_probe"` immediately after `"web_audit"`:

```python
MODULE_ORDER = ["port_scanner", "cve_lookup", "dns_enum", "osint_fetcher",
                "service_probe", "web_audit", "web_vuln_probe", "takeover_check",
                "email_audit", "nuclei_scan"]
```

- [ ] **Step 2: Import the entrypoint in the worker**

In `apps/api/workers/scan_worker.py`, add this import alongside the other `scanner_core` imports (near `from scanner_core.web_audit import audit_web`):

```python
from scanner_core.web_vuln_probe import probe_web_vulns
```

- [ ] **Step 3: Add the guarded module block**

In `apps/api/workers/scan_worker.py`, immediately after the `web_audit` block and its `_aborted(...)` check (after the lines that end the `if "web_audit" in allowed_modules:` block and the `aborted = _aborted(...)` / `if aborted: return ...` that follows it), insert:

```python
        if "web_vuln_probe" in allowed_modules:
            _set_module_running(db, scan, "web_vuln_probe")
            modules_run.append("web_vuln_probe")
            try:
                findings.extend(probe_web_vulns(target, ports))
                logger.info("scan_worker: scan=%s web_vuln_probe found %d findings", scan_id, len(findings))
            except Exception as exc:
                errors["web_vuln_probe"] = str(exc)

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}
```

- [ ] **Step 4: Verify wiring (import + ordering) and full suite**

Run (from repo root):
```bash
cd apps/api && ./venv/Scripts/python.exe -c "from constants import MODULE_ORDER; assert MODULE_ORDER.index('web_vuln_probe') == MODULE_ORDER.index('web_audit') + 1, MODULE_ORDER; import workers.scan_worker; print('wiring OK')"
```
Expected: prints `wiring OK` with no import error.

Then run the whole scanner test suite (from repo root):
```bash
apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/ -v
```
Expected: PASS (entire suite, no regressions).

- [ ] **Step 5: Commit**

```bash
git add apps/api/constants.py apps/api/workers/scan_worker.py
git commit -m "feat(scanner): wire web_vuln_probe into the scan pipeline"
```

---

### Task 7: Live smoke test (manual verification — optional but recommended)

**Files:** none (verification only).

**Interfaces:** Consumes the running stack + the local DVWA container (`localhost:8080`).

- [ ] **Step 1: Probe the local DVWA directly (no auth)**

Run (from repo root):
```bash
apps/api/venv/Scripts/python.exe -c "from scanner_core.web_vuln_probe import probe_web_vulns; from scanner_core.models import PortResult; fs = probe_web_vulns('localhost', [PortResult(port=8080, protocol='tcp', state='open', service='http')]); [print(f.severity, f.title, '->', f.target) for f in fs]; print('total:', len(fs))"
```
Expected: zero or more findings printed without errors. (DVWA's unauthenticated surface is limited; testphp.vulnweb.com is a better positive target — substitute host `testphp.vulnweb.com` / port 80 if you want to confirm SQLi/XSS hits. Only scan targets you are authorised to test.)

- [ ] **Step 2: Confirm timeout safety**

Confirm the call returns within ~`MODULE_DEADLINE_SECONDS` (45s) even on a slow target. No commit for this task.

---

## Self-Review

**1. Spec coverage:**
- Shared HTTP helper (no duplication) → Task 1. ✓
- Module + entrypoint `probe_web_vulns` → Tasks 2–5. ✓
- Bounded crawler (links + forms, same-host, page cap) → Tasks 3–4. ✓
- All five detector classes with FP guards → Tasks 2 & 5. ✓
- Budget/deadline (`MAX_PAGES_CRAWLED`, `MAX_INJECTION_POINTS`, `MAX_PARAMS_PER_POINT`, probe `HTTP_TIMEOUT`, `MODULE_DEADLINE_SECONDS`) → Task 2 constants, enforced in Tasks 4–5; page-budget test in Task 4. ✓
- Non-destructive payloads → Task 2 payload set. ✓
- Never raises to worker → `probe_web_vulns` try/except, `http_common.get`/`_request` swallow errors → Tasks 1/5. ✓
- Wiring into `MODULE_ORDER` after `web_audit` + worker block → Task 6. ✓
- `category="web_vuln"`, `source="web_vuln_probe"` → `_finding` helper, Task 5. ✓
- Tests (detectors, crawler, discovery+budget, e2e respx, FP guards, web_audit regression) → Tasks 1–5. ✓
- Unauthenticated only / no frontend / no new deps → respected throughout. ✓

**2. Placeholder scan:** No TBD/TODO; every code step has complete code; commands have expected output. ✓

**3. Type consistency:** `_Budget(deadline, pages_left)`, `InjectionPoint(url, method, params)`, detector signatures, `http_common.base_urls`/`get`, and `probe_web_vulns(host, ports)` are used identically across Tasks 1, 4, 5, 6. `_finding(...)` argument order matches all call sites in Task 5. The `http_common` import in `web_vuln_probe` is introduced in Task 4 (`get`) and extended in Task 5 (`USER_AGENT`, `base_urls`). ✓
