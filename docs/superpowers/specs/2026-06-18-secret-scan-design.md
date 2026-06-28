# Exposed Secret & Credential Detection (`secret_scan`) — Design

**Date:** 2026-06-18
**Status:** Approved (design)
**Author:** thridev + Claude

## Problem

The scan pipeline does almost nothing for exposed secrets. `web_audit` notes
that `/.env` or `/.git/HEAD` return HTTP 200 but never fetches their contents,
and no module scans reachable page/JS content for hardcoded API keys, tokens,
private keys, or database credentials. Real attack surfaces routinely leak
secrets in front-end JS bundles, exposed `.env`/config files, and readable
`.git` metadata — all of which currently pass through undetected.

## Goal

Add a scanner module that fetches reachable web content and exposed
config/.git files and detects leaked secrets, producing `Finding` objects that
feed the risk score (component 6: non-CVE findings) and severity summary.

## Non-Goals (v1)

- **Breach-corpus / HaveIBeenPwned email lookups** (external, mostly paid API).
- **Full `.git` repository reconstruction** (pack/object walking). v1 fetches a
  couple of known `.git` text files only.
- Authenticated scanning; binary-asset analysis; source-map reconstruction.
- Frontend changes — generic `Finding`s already render in the findings panel.
- New runtime dependencies — uses `httpx` (present) + stdlib `re`/`math`/`html.parser`.

## Architecture

New module: `packages/scanner_core/secret_scan.py`.

Public entrypoint:

```python
def scan_for_secrets(host: str, ports: Iterable[PortResult]) -> list[Finding]
```

Placed in `MODULE_ORDER` immediately after `web_vuln_probe`. Reuses
`http_common.base_urls` and `http_common.get`. All requests are GET; the module
is read-only and never raises out to the worker.

### Internal units

1. **`http_common.base_urls(host, ports)`** — derive HTTP(S) base URLs (shared).

2. **Asset/link extractor — `_AssetExtractor(HTMLParser)`** — a focused stdlib
   parser collecting, per page: `<script src>` and `<link href>` asset URLs, and
   same-host `<a href>` page links for the shallow crawl. (Distinct from
   `web_vuln_probe._InputExtractor`, which extracts injectable params/forms; the
   two modules stay decoupled rather than sharing a crawler in v1.)

3. **Content collector — `_collect(client, bases, budget)`** — for each base:
   - Probe the curated `SENSITIVE_PATHS` list and scan the contents of any that
     return 200 with a text-like body.
   - Fetch `/.git/config` and `/.git/HEAD`; if present, flag exposure and scan
     `config` for credentials in remote URLs.
   - Shallow same-host BFS over HTML pages (bounded by `MAX_PAGES_CRAWLED`):
     scan each page body, enqueue same-host `<a href>` links, and fetch+scan
     linked JS/JSON/text assets (bounded by `MAX_ASSETS`).
   - Only text-like resources are scanned (`Content-Type` text/js/json or
     extension in `.js/.json/.txt/.map/.yml/.yaml/.env`); only the first
     `MAX_BYTES_PER_RESOURCE` of any body is scanned.

4. **Detectors:**
   - `SECRET_PATTERNS: list[tuple[str, str, re.Pattern]]` — `(name, severity,
     regex)` for high-confidence provider secrets: AWS access-key id + secret
     key, Google API key, GCP service-account JSON, Stripe `sk_live`, Slack
     `xox*`, GitHub `gh[pousr]_*`, SendGrid, Twilio, PEM private keys, and DB
     connection strings with inline creds (`postgres://user:pass@`,
     `mongodb://…`). JWTs matched separately at MEDIUM.
   - `_shannon_entropy(s: str) -> float` and gated entropy: flag a high-entropy
     string (entropy ≥ threshold, length ≥ 20) **only** when it appears in an
     assignment context (`(api[_-]?key|token|secret|password|passwd|pwd)` near
     `=`/`:` then a quoted/bare value).
   - `_scan_content(url, content) -> list[Finding]` — run patterns + gated
     entropy, dedupe within the resource by `(name, redacted_value)`.

5. **`_redact(secret: str) -> str`** — mask the middle, keeping a short prefix
   and suffix (e.g. `AKIA…AB12`). Findings store only redacted evidence.

6. **`scan_for_secrets(host, ports)`** — orchestrate inside one `httpx.Client`
   with a `_Budget` (monotonic deadline + request counter), dedupe findings by
   `(title, target, evidence)`, log a count, and return.

### Severity mapping

| Finding | Severity |
|---|---|
| PEM private key, cloud secret key (AWS secret / GCP SA), DB URI with creds, `.git` remote with creds | CRITICAL or HIGH |
| Provider API tokens (Stripe/Slack/GitHub/Google/SendGrid/Twilio) | HIGH |
| JWT, gated-entropy generic secret | MEDIUM |
| Exposed `.env`/`.git` file with no parsed secret (the exposure itself) | MEDIUM |

`category="secret_exposure"`, `source="secret_scan"` on every finding.

### Budget / timeout safety

| Constant | Value |
|---|---|
| `MAX_PAGES_CRAWLED` | 10 |
| `MAX_ASSETS` | 25 |
| `MAX_BYTES_PER_RESOURCE` | 2_000_000 (2 MB) |
| `HTTP_TIMEOUT` | 8s/request |
| `MODULE_DEADLINE_SECONDS` | 45s |

A `time.monotonic()` deadline plus global request/asset/page counters gate every
fetch; when a cap or the deadline is hit the module stops cleanly and returns the
findings collected so far. All network/parse errors are caught and logged.

### Safety / authorization

- Gated upstream by `i_own_this_target` + the SSRF guard (`validate_scan_target`).
- Read-only: GET requests only; no payloads, nothing modified.
- Secrets are **redacted** in finding evidence before storage/display — the full
  secret value is never persisted to `result_json` or shown in the UI.

## Wiring

- `apps/api/constants.py`: insert `"secret_scan"` into `MODULE_ORDER` directly
  after `"web_vuln_probe"`.
- `apps/api/workers/scan_worker.py`: import `scan_for_secrets`; add a guarded
  module block after the `web_vuln_probe` block (mirroring the established
  pattern: `_set_module_running` → `modules_run.append` → `try:
  findings.extend(scan_for_secrets(target, ports))` / `except Exception as exc:
  errors["secret_scan"] = str(exc)`), followed by the standard `_aborted(...)`
  boundary check.

## Testing

`packages/scanner_core/tests/test_secret_scan.py`:

- **Detector unit tests:** each provider pattern matches a representative
  sample; benign strings don't. The redactor masks the middle and preserves a
  short prefix/suffix.
- **Entropy gating:** a high-entropy value in an assignment (`api_key = "…"`) is
  flagged; the same value in bare minified JS is not.
- **End-to-end (respx):** a page linking a JS asset that leaks an AWS key yields
  a HIGH/CRITICAL finding whose evidence is redacted; an exposed `/.env` with
  `SECRET_KEY=…` is fetched and flagged; a clean site yields no findings.
- **Budget/deadline:** crawling/asset-fetching stops at the configured caps and
  an exceeded deadline halts further requests.

## Risk-score impact (expected)

On real targets that leak keys in JS or expose `.env`/`.git`, the module surfaces
HIGH/CRITICAL `Finding`s, driving risk component 6 and the severity summary —
closing one of the platform's largest current blind spots.
