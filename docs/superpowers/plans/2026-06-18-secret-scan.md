# Exposed Secret & Credential Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `secret_scan` scanner module that fetches reachable web content, linked JS/assets, and exposed config/.env/.git files, then detects leaked secrets (curated provider patterns + gated entropy) and emits redacted `Finding`s that feed the risk score.

**Architecture:** A new module `packages/scanner_core/secret_scan.py` reuses `http_common.base_urls`/`get`, shallow-crawls same-host HTML pages, fetches linked text/JS assets and a curated list of sensitive files, and scans every text body with `SECRET_PATTERNS` + an assignment-context entropy check. Findings carry redacted evidence. Hard page/asset caps plus a 45s deadline keep it inside the scan budget. Wired into `MODULE_ORDER` after `web_vuln_probe`.

**Tech Stack:** Python, `httpx` (already a dependency), stdlib `re`/`math`/`html.parser`/`urllib.parse`, Pydantic `Finding`. Tests use `pytest` + `respx` (already present).

## Global Constraints

- No new runtime dependencies — only `httpx` + Python stdlib.
- Reuses `scanner_core/http_common.py` (`base_urls`, `get`, `USER_AGENT`) — do not re-implement those.
- All findings use `category="secret_exposure"` and `source="secret_scan"`.
- `Finding` model fields (from `scanner_core.models`): `title`, `severity` (CRITICAL|HIGH|MEDIUM|LOW|INFO), `category`, `description`, `target`, `evidence`, `remediation`, `source`, `references`.
- Read-only: GET requests only; nothing is modified. The module MUST NOT raise out to the worker (catch + log).
- Secrets MUST be redacted in finding `evidence` (never store/display the full secret value).
- Budgets fixed (conservative): `MAX_PAGES_CRAWLED=10`, `MAX_ASSETS=25`, `MAX_BYTES_PER_RESOURCE=2_000_000`, `HTTP_TIMEOUT=8`, `MODULE_DEADLINE_SECONDS=45`; entropy gating `ENTROPY_MIN=4.0`, `ENTROPY_MIN_LEN=20`.
- Tests run with: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/ -v` (from repo root `C:\PROJECTS\easm`).
- Commits: `feat(scanner): ...`, NO `Co-Authored-By` trailer.

---

### Task 1: Detection core (patterns, entropy, redaction, content scan)

**Files:**
- Create: `packages/scanner_core/secret_scan.py`
- Test: `packages/scanner_core/tests/test_secret_scan.py`

**Interfaces:**
- Consumes: `scanner_core.models.Finding`.
- Produces:
  - All module constants (budgets, `SENSITIVE_PATHS`, `GIT_PATHS`, `TEXT_EXTENSIONS`, entropy thresholds).
  - `SECRET_PATTERNS: list[tuple[str, str, re.Pattern]]`, `ASSIGNMENT_RE: re.Pattern`
  - `_shannon_entropy(s: str) -> float`
  - `_redact(secret: str) -> str`
  - `_finding(title: str, severity: str, target: str, evidence: str) -> Finding`
  - `_exposure_finding(url: str) -> Finding`
  - `_scan_content(url: str, content: str) -> list[Finding]`

- [ ] **Step 1: Write the failing test**

```python
# packages/scanner_core/tests/test_secret_scan.py
from scanner_core import secret_scan as ss


def test_patterns_match_representative_secrets():
    samples = {
        "AWS access key ID": "AKIAIOSFODNN7EXAMPLE",
        "Google API key": "AIzaSyA1234567890abcdefghijklmnopqrstu1",
        "GitHub token": "ghp_" + "a" * 36,
        "Private key (PEM)": "-----BEGIN RSA PRIVATE KEY-----",
        "Database connection string with credentials": "postgres://admin:s3cret@db.host:5432/app",
    }
    for name, sample in samples.items():
        findings = ss._scan_content("http://t/app.js", sample)
        assert any(name in f.title for f in findings), f"{name} not detected in {sample!r}"


def test_clean_content_yields_no_findings():
    assert ss._scan_content("http://t/app.js", "const x = 1; // nothing secret here") == []


def test_entropy_gated_to_assignment_context():
    token = "Zk8s9Qw2Lp7Xn4Vb1Tc6Yr3Hg5Df0Aj"  # 32 chars, high entropy
    # In an assignment context -> flagged
    assigned = f'api_key = "{token}"'
    assert any("entropy" in f.title.lower() for f in ss._scan_content("http://t/a.js", assigned))
    # Bare in minified JS (no assignment keyword) -> not flagged
    bare = f'function(){{return "{token}"}}'
    assert not any("entropy" in f.title.lower() for f in ss._scan_content("http://t/a.js", bare))


def test_redact_masks_middle():
    assert ss._redact("AKIAIOSFODNN7EXAMPLE") == "AKIA********MPLE"
    assert ss._redact("short") == "*****"


def test_findings_are_redacted_and_tagged():
    findings = ss._scan_content("http://t/app.js", "key=AKIAIOSFODNN7EXAMPLE")
    f = next(f for f in findings if "AWS access key" in f.title)
    assert f.category == "secret_exposure"
    assert f.source == "secret_scan"
    assert "AKIAIOSFODNN7EXAMPLE" not in (f.evidence or "")  # full secret never stored
    assert "AKIA" in (f.evidence or "")  # redacted form present
```

- [ ] **Step 2: Run test to verify it fails**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_secret_scan.py -v`
Expected: FAIL — `ModuleNotFoundError`/`AttributeError`.

- [ ] **Step 3: Write minimal implementation**

```python
# packages/scanner_core/secret_scan.py
"""
secret_scan.py
--------------
Detects exposed secrets and credentials on a target's web surface. Fetches
reachable HTML pages, their linked JS/text assets, and a curated set of exposed
config/.env/.git files, then scans every text body for hardcoded secrets using
curated provider patterns plus an assignment-context entropy check.

All matched secrets are REDACTED in finding evidence. The module is read-only
(GET only), hard-bounded by page/asset caps and a wall-clock deadline, and never
raises out to the worker. Shared HTTP helpers come from http_common.
"""

import logging
import math
import re
from typing import Optional

try:
    from .models import Finding
except ImportError:  # pragma: no cover
    from models import Finding

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 8
MAX_BASE_URLS = 2
MAX_PAGES_CRAWLED = 10
MAX_ASSETS = 25
MAX_BYTES_PER_RESOURCE = 2_000_000
MODULE_DEADLINE_SECONDS = 45
ENTROPY_MIN = 4.0
ENTROPY_MIN_LEN = 20

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.dev",
    "/config.json", "/config.yaml", "/config.yml",
    "/credentials", "/.aws/credentials", "/secrets.json",
]
GIT_PATHS = ["/.git/config", "/.git/HEAD"]
TEXT_EXTENSIONS = (".js", ".json", ".txt", ".map", ".yml", ".yaml", ".env", ".config", ".xml", ".ts")

# (name, severity, compiled pattern). Patterns are deliberately specific to keep
# false positives low; generic/unknown tokens are handled by gated entropy.
SECRET_PATTERNS: list[tuple[str, str, "re.Pattern[str]"]] = [
    ("AWS secret access key", "CRITICAL", re.compile(r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("AWS access key ID", "HIGH", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", "HIGH", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("GCP service account key", "CRITICAL", re.compile(r'"type"\s*:\s*"service_account"')),
    ("Stripe secret key", "HIGH", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Slack token", "HIGH", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub token", "HIGH", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("SendGrid API key", "HIGH", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("Twilio API key", "HIGH", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("Private key (PEM)", "CRITICAL", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Database connection string with credentials", "CRITICAL", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@[^\s/'\"]+")),
    ("JSON Web Token (JWT)", "MEDIUM", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
]

ASSIGNMENT_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key)"
    r"['\"]?\s*[:=]\s*['\"]([^'\"\s]{%d,})['\"]" % ENTROPY_MIN_LEN
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(secret: str) -> str:
    s = (secret or "").strip()
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}{'*' * 8}{s[-4:]}"


def _finding(title: str, severity: str, target: str, evidence: str) -> Finding:
    return Finding(
        title=f"Exposed secret: {title}",
        severity=severity,
        category="secret_exposure",
        description=f"A {title} was found in content served at {target}.",
        target=target,
        evidence=f"Match (redacted): {evidence}",
        remediation="Rotate the exposed credential immediately and remove it from web-served content; load secrets from server-side config or a secrets manager.",
        source="secret_scan",
    )


def _exposure_finding(url: str) -> Finding:
    return Finding(
        title="Exposed sensitive file",
        severity="MEDIUM",
        category="secret_exposure",
        description=f"A sensitive file is publicly reachable at {url}.",
        target=url,
        evidence="HTTP 200",
        remediation="Block public access to this file at the web server and rotate any secrets it contained.",
        source="secret_scan",
    )


def _scan_content(url: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    reported: set[str] = set()  # redacted values already reported (dedup pattern + entropy)
    snippet = (content or "")[:MAX_BYTES_PER_RESOURCE]

    for name, severity, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(snippet):
            redacted = _redact(match.group(0))
            if redacted in reported:
                continue
            reported.add(redacted)
            findings.append(_finding(name, severity, url, redacted))

    for match in ASSIGNMENT_RE.finditer(snippet):
        value = match.group(1)
        if len(value) < ENTROPY_MIN_LEN or _shannon_entropy(value) < ENTROPY_MIN:
            continue
        redacted = _redact(value)
        if redacted in reported:
            continue
        reported.add(redacted)
        findings.append(_finding("High-entropy secret in assignment", "MEDIUM", url, redacted))

    return findings
```

> Dedup is keyed on the redacted value in a single `set[str]`, so a value caught by a specific pattern won't be re-reported by the entropy pass (and vice versa).

- [ ] **Step 4: Run test to verify it passes**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_secret_scan.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/scanner_core/secret_scan.py packages/scanner_core/tests/test_secret_scan.py
git commit -m "feat(scanner): add secret_scan detection core (patterns, entropy, redaction)"
```

---

### Task 2: Asset/link HTML extractor

**Files:**
- Modify: `packages/scanner_core/secret_scan.py`
- Test: `packages/scanner_core/tests/test_secret_scan.py`

**Interfaces:**
- Consumes: nothing from prior tasks.
- Produces: `_AssetExtractor(HTMLParser)` with `assets: list[str]` (from `<script src>` / `<link href>`) and `links: list[str]` (from `<a href>`).

- [ ] **Step 1: Write the failing test**

```python
# append to packages/scanner_core/tests/test_secret_scan.py
def test_asset_extractor_collects_scripts_links_and_anchors():
    html = """
    <html><head>
      <script src="/static/app.bundle.js"></script>
      <link href="/static/config.json" rel="preload">
    </head><body>
      <a href="/about">about</a>
      <a href="https://cdn.other/x.js">offsite</a>
    </body></html>
    """
    ex = ss._AssetExtractor()
    ex.feed(html)
    assert "/static/app.bundle.js" in ex.assets
    assert "/static/config.json" in ex.assets
    assert "/about" in ex.links
    assert "https://cdn.other/x.js" in ex.links
```

- [ ] **Step 2: Run test to verify it fails**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_secret_scan.py::test_asset_extractor_collects_scripts_links_and_anchors -v`
Expected: FAIL — `AttributeError: ... '_AssetExtractor'`.

- [ ] **Step 3: Write minimal implementation**

Add the import at the top of `secret_scan.py` (with the other imports):

```python
from html.parser import HTMLParser
```

Then add (after `_scan_content`):

```python
class _AssetExtractor(HTMLParser):
    """Collect script/link asset URLs and anchor page links from an HTML page."""

    def __init__(self) -> None:
        super().__init__()
        self.assets: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.assets.append(a["src"])
        elif tag == "link" and a.get("href"):
            self.assets.append(a["href"])
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        self.handle_starttag(tag, attrs)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_secret_scan.py::test_asset_extractor_collects_scripts_links_and_anchors -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/scanner_core/secret_scan.py packages/scanner_core/tests/test_secret_scan.py
git commit -m "feat(scanner): add asset/link extractor to secret_scan"
```

---

### Task 3: Budget, resource helpers, and single-URL scan

**Files:**
- Modify: `packages/scanner_core/secret_scan.py`
- Test: `packages/scanner_core/tests/test_secret_scan.py`

**Interfaces:**
- Consumes: `_scan_content` (Task 1); constants (Task 1).
- Produces:
  - `@dataclass _Budget(deadline: float, assets_left: int)` with `expired() -> bool`
  - `_is_text_like(resp: httpx.Response, url: str) -> bool`
  - `_body(resp: httpx.Response) -> str`
  - `_scan_url(client: httpx.Client, url: str, scanned: set[str], findings: list[Finding]) -> Optional[httpx.Response]`

- [ ] **Step 1: Write the failing test**

```python
# append to packages/scanner_core/tests/test_secret_scan.py
import httpx
import respx


@respx.mock
def test_scan_url_scans_text_asset_and_records_finding():
    respx.get("http://t.test/app.js").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/javascript"},
                                    text='var k="AKIAIOSFODNN7EXAMPLE";')
    )
    scanned: set[str] = set()
    findings: list = []
    with httpx.Client() as client:
        resp = ss._scan_url(client, "http://t.test/app.js", scanned, findings)
    assert resp is not None and resp.status_code == 200
    assert any("AWS access key" in f.title for f in findings)
    # dedup guard: scanning the same URL again does nothing
    with httpx.Client() as client:
        assert ss._scan_url(client, "http://t.test/app.js", scanned, findings) is None


@respx.mock
def test_scan_url_skips_non_200_and_binary():
    respx.get("http://t.test/missing").mock(return_value=httpx.Response(404, text="nope"))
    respx.get("http://t.test/img.png").mock(
        return_value=httpx.Response(200, headers={"content-type": "image/png"}, text="AKIAIOSFODNN7EXAMPLE")
    )
    findings: list = []
    with httpx.Client() as client:
        assert ss._scan_url(client, "http://t.test/missing", set(), findings) is None
        # binary content-type: response returned but NOT scanned
        resp = ss._scan_url(client, "http://t.test/img.png", set(), findings)
    assert resp is not None
    assert findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_secret_scan.py -k "scan_url" -v`
Expected: FAIL — `AttributeError` (`_scan_url` not defined).

- [ ] **Step 3: Write minimal implementation**

Add these imports at the top of `secret_scan.py` (extend the existing block):

```python
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from .http_common import get
```

> `secret_scan` is in the same package as `http_common`; `from .http_common import get` works under the normal import path (mirror the `try/except` only if a later task needs it for the script-mode fallback — `get` does not).

Then add (after `_AssetExtractor`):

```python
@dataclass
class _Budget:
    deadline: float
    assets_left: int

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline


def _is_text_like(resp: httpx.Response, url: str) -> bool:
    ctype = resp.headers.get("content-type", "").lower()
    if any(t in ctype for t in ("text", "javascript", "json", "xml", "yaml")):
        return True
    path = urlparse(url).path.lower()
    return path.endswith(TEXT_EXTENSIONS)


def _body(resp: httpx.Response) -> str:
    return (resp.text or "")[:MAX_BYTES_PER_RESOURCE]


def _scan_url(
    client: httpx.Client,
    url: str,
    scanned: set[str],
    findings: list[Finding],
) -> Optional[httpx.Response]:
    """Fetch `url` once; if it returns 200 with a text-like body, scan it for
    secrets (appending to `findings`). Returns the response so the caller can
    extract assets/links, or None if already scanned / not fetched."""
    if url in scanned:
        return None
    scanned.add(url)
    resp = get(client, url, timeout=HTTP_TIMEOUT)
    if resp is None or resp.status_code != 200:
        return None
    if _is_text_like(resp, url):
        findings.extend(_scan_content(url, _body(resp)))
    return resp
```

- [ ] **Step 4: Run test to verify it passes**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_secret_scan.py -k "scan_url" -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/scanner_core/secret_scan.py packages/scanner_core/tests/test_secret_scan.py
git commit -m "feat(scanner): add budget and single-URL scan to secret_scan"
```

---

### Task 4: Orchestration entrypoint `scan_for_secrets`

**Files:**
- Modify: `packages/scanner_core/secret_scan.py`
- Test: `packages/scanner_core/tests/test_secret_scan.py`

**Interfaces:**
- Consumes: `_Budget`, `_is_text_like`, `_scan_url` (Task 3); `_AssetExtractor` (Task 2); `_exposure_finding` (Task 1); `http_common.base_urls`/`get`/`USER_AGENT`.
- Produces: `scan_for_secrets(host: str, ports: Iterable[PortResult]) -> list[Finding]`

- [ ] **Step 1: Write the failing test**

```python
# append to packages/scanner_core/tests/test_secret_scan.py
@respx.mock
def test_scan_for_secrets_finds_key_in_linked_js():
    from scanner_core.models import PortResult
    page = '<html><script src="/static/app.js"></script></html>'
    respx.get("http://v.test:80/").mock(return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=page))
    respx.get("http://v.test:80/static/app.js").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/javascript"},
                                    text='const token="ghp_' + "b" * 36 + '";')
    )
    # everything else (sensitive paths, .git, /about, etc.) -> 404
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="nf"))

    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    findings = ss.scan_for_secrets("v.test", ports)
    gh = [f for f in findings if "GitHub token" in f.title]
    assert gh, f"expected GitHub token finding, got {[f.title for f in findings]}"
    assert gh[0].severity == "HIGH"
    assert gh[0].category == "secret_exposure"
    assert "ghp_bbbb" not in (gh[0].evidence or "")  # redacted


@respx.mock
def test_scan_for_secrets_flags_exposed_env_contents():
    from scanner_core.models import PortResult
    respx.get("http://e.test:80/.env").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/plain"},
                                    text="SECRET_KEY=AKIAIOSFODNN7EXAMPLE\nDEBUG=1")
    )
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="nf"))
    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    findings = ss.scan_for_secrets("e.test", ports)
    assert any(f.title == "Exposed sensitive file" for f in findings)
    assert any("AWS access key" in f.title for f in findings)


@respx.mock
def test_scan_for_secrets_clean_site_has_no_findings():
    from scanner_core.models import PortResult
    respx.get("http://safe.test:80/").mock(return_value=httpx.Response(200, headers={"content-type": "text/html"}, text="<html>ok</html>"))
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="nf"))
    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    assert ss.scan_for_secrets("safe.test", ports) == []


def test_scan_for_secrets_returns_empty_without_http_ports():
    from scanner_core.models import PortResult
    ports = [PortResult(port=22, protocol="tcp", state="open", service="ssh")]
    assert ss.scan_for_secrets("nohttp.test", ports) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_secret_scan.py -k "scan_for_secrets" -v`
Expected: FAIL — `AttributeError: ... 'scan_for_secrets'`.

- [ ] **Step 3: Write minimal implementation**

Extend the imports at the top of `secret_scan.py`:
- Extend the models import to `from .models import Finding, PortResult` (and the `except ImportError` fallback to `from models import Finding, PortResult`).
- Extend the typing import to `from typing import Iterable, Optional`.
- Extend the http_common import to `from .http_common import USER_AGENT, base_urls, get`.

Then add (after `_scan_url`):

```python
def scan_for_secrets(host: str, ports: Iterable[PortResult]) -> list[Finding]:
    """Scan the host's HTTP services for exposed secrets and credentials."""
    bases = base_urls(host, list(ports))[:MAX_BASE_URLS]
    if not bases:
        return []
    budget = _Budget(deadline=time.monotonic() + MODULE_DEADLINE_SECONDS, assets_left=MAX_ASSETS)
    findings: list[Finding] = []
    scanned: set[str] = set()
    with httpx.Client(verify=False, headers={"User-Agent": USER_AGENT}, follow_redirects=False) as client:
        try:
            for base in bases:
                netloc = urlparse(base).netloc

                # Exposed config/.env + .git files: scan contents and flag exposure.
                for path in SENSITIVE_PATHS + GIT_PATHS:
                    if budget.expired():
                        break
                    resp = _scan_url(client, base + path, scanned, findings)
                    if resp is not None and resp.status_code == 200:
                        findings.append(_exposure_finding(base + path))

                # Shallow same-host crawl: scan each page body + linked text assets.
                to_visit = [base]
                page_seen: set[str] = set()
                pages = 0
                while to_visit and pages < MAX_PAGES_CRAWLED and not budget.expired():
                    page = to_visit.pop(0)
                    if page in page_seen:
                        continue
                    page_seen.add(page)
                    pages += 1
                    resp = _scan_url(client, page, scanned, findings)
                    if resp is None or "html" not in resp.headers.get("content-type", "").lower():
                        continue
                    extractor = _AssetExtractor()
                    try:
                        extractor.feed(resp.text or "")
                    except Exception:  # pragma: no cover - defensive
                        continue
                    for src in extractor.assets:
                        if budget.assets_left <= 0 or budget.expired():
                            break
                        asset = urljoin(page, src).split("#")[0]
                        if urlparse(asset).netloc != netloc:
                            continue
                        budget.assets_left -= 1
                        _scan_url(client, asset, scanned, findings)
                    for href in extractor.links:
                        nxt = urljoin(page, href).split("#")[0]
                        if (urlparse(nxt).netloc == netloc and nxt not in page_seen
                                and nxt not in to_visit and len(to_visit) < MAX_PAGES_CRAWLED):
                            to_visit.append(nxt)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("secret_scan: failed for %s: %s", host, exc)

    deduped: dict[tuple[str, Optional[str], Optional[str]], Finding] = {}
    for f in findings:
        deduped[(f.title, f.target, f.evidence)] = f
    result = list(deduped.values())
    logger.info("secret_scan: %d findings for %s", len(result), host)
    return result
```

- [ ] **Step 4: Run the full module test suite to verify it passes**

Run: `apps/api/venv/Scripts/python.exe -m pytest packages/scanner_core/tests/test_secret_scan.py -v`
Expected: PASS (all secret_scan tests).

- [ ] **Step 5: Commit**

```bash
git add packages/scanner_core/secret_scan.py packages/scanner_core/tests/test_secret_scan.py
git commit -m "feat(scanner): add scan_for_secrets orchestration entrypoint"
```

---

### Task 5: Wire `secret_scan` into the scan pipeline

**Files:**
- Modify: `apps/api/constants.py` (the `MODULE_ORDER` list)
- Modify: `apps/api/workers/scan_worker.py` (import + guarded module block)

**Interfaces:**
- Consumes: `scan_for_secrets` (Task 4).
- Produces: `"secret_scan"` present in `MODULE_ORDER`; worker executes it after `web_vuln_probe`.

- [ ] **Step 1: Add the module to `MODULE_ORDER`**

In `apps/api/constants.py`, change the `MODULE_ORDER` list to insert `"secret_scan"` immediately after `"web_vuln_probe"`:

```python
MODULE_ORDER = ["port_scanner", "cve_lookup", "dns_enum", "osint_fetcher",
                "service_probe", "web_audit", "web_vuln_probe", "secret_scan",
                "takeover_check", "email_audit", "nuclei_scan"]
```

- [ ] **Step 2: Import the entrypoint in the worker**

In `apps/api/workers/scan_worker.py`, add this import alongside the other `scanner_core` imports (near `from scanner_core.web_vuln_probe import probe_web_vulns`):

```python
from scanner_core.secret_scan import scan_for_secrets
```

- [ ] **Step 3: Add the guarded module block**

In `apps/api/workers/scan_worker.py`, immediately after the `web_vuln_probe` block and its `_aborted(...)` check, insert:

```python
        if "secret_scan" in allowed_modules:
            _set_module_running(db, scan, "secret_scan")
            modules_run.append("secret_scan")
            try:
                findings.extend(scan_for_secrets(target, ports))
                logger.info("scan_worker: scan=%s secret_scan found %d findings", scan_id, len(findings))
            except Exception as exc:
                errors["secret_scan"] = str(exc)

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}
```

- [ ] **Step 4: Verify wiring (import + ordering) and full suite**

Run (from repo root):
```bash
cd apps/api && ./venv/Scripts/python.exe -c "from constants import MODULE_ORDER; assert MODULE_ORDER.index('secret_scan') == MODULE_ORDER.index('web_vuln_probe') + 1, MODULE_ORDER; import workers.scan_worker; print('wiring OK')"
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
git commit -m "feat(scanner): wire secret_scan into the scan pipeline"
```

---

### Task 6: Live smoke test (manual verification — optional but recommended)

**Files:** none (verification only).

- [ ] **Step 1: Probe a target directly**

Run (from repo root):
```bash
apps/api/venv/Scripts/python.exe -c "from scanner_core.secret_scan import scan_for_secrets; from scanner_core.models import PortResult; fs = scan_for_secrets('localhost', [PortResult(port=8080, protocol='tcp', state='open', service='http')]); [print(f.severity, f.title, '->', f.target) for f in fs]; print('total:', len(fs))"
```
Expected: zero or more findings printed without errors, returning within ~`MODULE_DEADLINE_SECONDS` (45s). (DVWA won't necessarily leak secrets; substitute a target you control that serves a JS bundle or `.env` to see positive hits. Only scan targets you are authorised to test.)

- [ ] **Step 2: Confirm timeout safety** — confirm the call returns within the deadline even on a slow target. No commit for this task.

---

## Self-Review

**1. Spec coverage:**
- Module + entrypoint `scan_for_secrets` → Tasks 1–4. ✓
- Source 1 (crawled pages + JS/assets) → `_AssetExtractor` (Task 2) + crawl/asset loop in Task 4. ✓
- Source 2 (exposed config/.env contents) → `SENSITIVE_PATHS` scanned via `_scan_url` + `_exposure_finding` (Task 1/4). ✓
- Source 3 (lightweight `.git`) → `GIT_PATHS` scanned + exposure flagged (Task 1/4). ✓
- Curated patterns + gated entropy → `SECRET_PATTERNS`/`ASSIGNMENT_RE`/`_shannon_entropy`/`_scan_content` (Task 1). ✓
- Redaction → `_redact`, enforced in `_finding`/`_scan_content`; test asserts full secret absent (Task 1). ✓
- Severity mapping → encoded in `SECRET_PATTERNS` + `_exposure_finding` (Task 1). ✓
- Budget/deadline + text-like + byte cap → `_Budget`/`_is_text_like`/`_body`/`MAX_*` (Tasks 1/3), enforced in Task 4. ✓
- Never raises to worker → try/except in `scan_for_secrets` + error-swallowing `get`/`_scan_url` (Tasks 3/4). ✓
- Wiring after `web_vuln_probe` → Task 5. ✓
- `category="secret_exposure"`, `source="secret_scan"` → `_finding`/`_exposure_finding` (Task 1). ✓
- No new deps; reuse http_common; GET-only → respected throughout. ✓

**2. Placeholder scan:** No TBD/TODO; every code step has complete code; commands have expected output. ✓

**3. Type consistency:** `_Budget(deadline, assets_left)`, `_scan_url(client, url, scanned, findings)`, `_scan_content(url, content)`, `_AssetExtractor.assets/links`, and `scan_for_secrets(host, ports)` are used identically across Tasks 3–5. The `http_common` import is introduced in Task 3 (`get`) and extended in Task 4 (`USER_AGENT`, `base_urls`); the models import is extended to add `PortResult` in Task 4 (consumed by the entrypoint signature) and typing extended to add `Iterable` in Task 4. ✓
