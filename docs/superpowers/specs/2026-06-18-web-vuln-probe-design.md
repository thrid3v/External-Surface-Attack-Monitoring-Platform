# Active Web Vulnerability Probe (`web_vuln_probe`) — Design

**Date:** 2026-06-18
**Status:** Approved (design)
**Author:** thridev + Claude

## Problem

The EASM scan pipeline currently performs only passive / template-based web
checks (`service_probe` headers + TLS, `web_audit` sensitive paths / CORS /
cookies, `nuclei_scan` templates). It does no **active** testing of request
parameters for injection-class vulnerabilities. Against application targets that
are full of such bugs (DVWA, testphp.vulnweb.com), the resulting risk score
under-represents real risk because no `Finding`s are produced for the most
impactful vulnerability classes.

## Goal

Add a new scanner module that actively (but conservatively and non-destructively)
tests discovered HTTP inputs for injection-class vulnerabilities, producing
`Finding` objects that feed the existing risk score (component 6: non-CVE
findings) and severity summary.

## Non-Goals (v1)

- **Authenticated scanning** (e.g. logging into DVWA). Unauthenticated only.
- Boolean/time-based blind SQLi, DOM XSS, SSRF, XXE, deserialization.
- A general-purpose crawler/spider. Crawling is intentionally shallow and bounded.
- Any frontend changes — generic `Finding`s already render in the findings panel.
- New runtime dependencies — uses `httpx` (already present) + stdlib `html.parser`.

## Architecture

New module: `packages/scanner_core/web_vuln_probe.py`.

Public entrypoint:

```python
def probe_web_vulns(host: str, ports: Iterable[PortResult]) -> list[Finding]
```

It is placed in `MODULE_ORDER` immediately after `web_audit`, so the
already-discovered HTTP ports are available and reused.

Base-URL derivation and the guarded GET are shared with `web_audit` via a new
`scanner_core/http_common.py` (`base_urls()`, `get()`, and the HTTP constants),
so the logic is defined once rather than duplicated across the two modules.

### Internal units

1. **`http_common.base_urls(host, ports)`** — derive `scheme://host:port` base
   URLs for HTTP services (shared with `web_audit`).

2. **Bounded crawler — `_discover_inputs(client, bases, budget)`**
   - GET each base root, parse HTML with a stdlib `HTMLParser` subclass.
   - Extract, **same-host only**:
     - `<a href>` links carrying query strings → injectable query params.
     - `<form>` elements → action URL, method (GET/POST), and
       input/textarea/select `name`s → injectable form fields.
   - Seed also from any base URL that already carries a query string.
   - Returns a deduped list of `InjectionPoint(url, method, params, target_param)`
     (internal dataclass), keyed by `(url, method, sorted(param names))`.

3. **Detectors** — one pure function per class. Each receives the baseline
   response, the injected response, and the payload, and returns
   `Optional[Finding]`:

   | Class | Payload(s) | Detection | Severity |
   |---|---|---|---|
   | Error-based SQLi | `'`, `' OR '1'='1` | DB error regex (MySQL/PG/MSSQL/Oracle/SQLite) present in injected response but **absent in baseline** | HIGH |
   | Reflected XSS | unique marker `easm<svg/onload=...>` | raw, **un-escaped** marker reflected in body | MEDIUM |
   | Path traversal / LFI | `../../../../etc/passwd`, `....//` variant | `root:.*:0:0:` (passwd) or `[extensions]`/`[fonts]` (win.ini) | HIGH |
   | Open redirect | `https://evil.example` | target appears in **`Location`** header of a 3xx (not body) | MEDIUM |
   | OS command injection | `;echo $((13337*31337))` and `| ` variant | product `418142369` present in body (proves execution, not mere reflection) | CRITICAL |

   FP-reduction is built into the detection rules: baseline diff for SQLi,
   un-escaped requirement for XSS, `Location`-only for open redirect, and an
   arithmetic-result marker for command injection (the literal payload never
   contains `418142369`, so reflection alone cannot trigger it).

4. **Injector — `_probe_point(client, point, budget, deadline)`**
   - Send one benign baseline request, then one crafted request per class per
     target param (a couple for SQLi/LFI).
   - GET params are injected into the query string; POST forms submit the marker
     in the targeted field with benign values elsewhere.
   - Each detector is run against (baseline, injected); findings are collected.
   - Respects the global request budget and deadline (checked between requests).

### Budget / timeout safety

Conservative, hard-bounded so the module cannot threaten the ~300s scan budget
(nuclei was already straining it):

| Constant | Value |
|---|---|
| `MAX_PAGES_CRAWLED` | 10 |
| `MAX_INJECTION_POINTS` | 15 |
| `MAX_PARAMS_PER_POINT` | 5 |
| `HTTP_TIMEOUT` (per request) | 6s |
| `MODULE_DEADLINE_SECONDS` | 45s |

A `time.monotonic()` deadline plus a global request counter gate every request.
When a cap or the deadline is reached, the module stops cleanly and returns the
findings collected so far. All network/parse errors are swallowed per base URL
(`logger.debug/warning`); the module never raises out to the worker.

### Safety / authorization

- Already gated upstream by `i_own_this_target` + the SSRF guard
  (`validate_scan_target`); the probe only ever runs against an
  already-validated target.
- Payloads are **non-destructive**: no `DROP`/`DELETE`, no `rm`, no `sleep`-based
  DoS. Command-injection detection uses an arithmetic echo, not a destructive
  command.
- All requests are GET, or POST only to forms the target itself exposed, with
  benign values in non-targeted fields.

## Wiring

- `apps/api/constants.py`: insert `"web_vuln_probe"` into `MODULE_ORDER` directly
  after `"web_audit"`.
- `apps/api/workers/scan_worker.py`: add a guarded block (mirroring the other
  modules) after the `web_audit` block:
  ```python
  if "web_vuln_probe" in allowed_modules:
      _set_module_running(db, scan, "web_vuln_probe")
      modules_run.append("web_vuln_probe")
      try:
          findings.extend(probe_web_vulns(target, ports))
      except Exception as exc:
          errors["web_vuln_probe"] = str(exc)
  ```
  followed by the standard `_aborted(...)` boundary check. Import
  `probe_web_vulns` at the top with the other scanner imports.
- Findings carry `category="web_vuln"`, `source="web_vuln_probe"`. They flow into
  the existing `findings` list → `calculate_risk_score` component 6 +
  `_build_severity_summary`.

## Testing

`packages/scanner_core/tests/test_web_vuln_probe.py`:

- **Detector unit tests** (pure): for each class, a vulnerable sample
  (body/headers) yields a `Finding`; a safe/baseline-matching sample yields
  `None`. Explicitly assert no SQLi FP when the error string is also present in
  the baseline, no cmd-injection FP on plain reflection, no open-redirect FP when
  the marker is only in the body.
- **Crawler/HTML-parse test**: parse a sample HTML string; assert links with
  query strings and form fields are extracted, and off-host links are ignored.
- **End-to-end (respx-mocked)**: a fake endpoint that returns a MySQL error when
  `'` is present yields a SQLi finding; a clean endpoint yields no findings.
- **Budget/deadline test**: assert crawling/probing stops at the configured caps
  and an exceeded deadline halts further requests.

## Risk-score impact (expected)

On DVWA / testphp.vulnweb.com, the probe should surface multiple HIGH/CRITICAL
`Finding`s (SQLi, LFI, command injection), driving component 6 toward its 30-pt
cap and raising the severity summary — meaningfully increasing and better
calibrating the overall risk score for application targets.
