/**
 * components/HttpPanel.tsx
 * ------------------------
 * Displays HTTP service findings in the "HTTP Findings" tab.
 * Shows what was discovered by service_probe.py on HTTP/HTTPS ports.
 *
 * PROPS:
 *   httpFindings: HttpFinding[]
 *     Each item contains:
 *       url, status_code, server_header, powered_by, cms_detected,
 *       missing_headers: string[], cert: CertInfo | null
 *
 * LAYOUT — one Card per HTTP finding (one per probed URL):
 *
 *   CARD HEADER:
 *     The URL as a clickable link (opens in new tab).
 *     Status code badge next to it:
 *       200 → green, 301/302 → blue, 403 → yellow, 500 → red
 *
 *   CARD BODY — three columns:
 *
 *   Column 1: "Server Info"
 *     Server header value     e.g. "Apache/2.4.51 (Ubuntu)"
 *     X-Powered-By value      e.g. "PHP/7.4.3"
 *     CMS detected            e.g. "WordPress 6.1" with a warning badge
 *       if CMS is detected — CMSs have frequent vulnerabilities.
 *     If all null: "No server info disclosed" (this is actually good practice)
 *
 *   Column 2: "Security Headers"
 *     List all 6 security headers.
 *     For each: green checkmark if present, red X if in missing_headers.
 *       ✓ Content-Security-Policy
 *       ✗ X-Frame-Options         ← red, this one is missing
 *       ✓ Strict-Transport-Security
 *       ...etc
 *     Below the list: a score "3/6 headers present" in muted text.
 *     If all 6 present: show a green "All security headers present" banner.
 *
 *   Column 3: "TLS Certificate" (only shown if cert is not null)
 *     Issuer, valid from, valid to, days until expiry.
 *     TLS version — flag TLS 1.0 or 1.1 as a HIGH severity finding
 *     with a red badge "Outdated TLS — upgrade to TLS 1.2+"
 *     If cert.is_expired: red banner "Certificate EXPIRED"
 *     If days_until_expiry < 30: yellow banner "Expires in {n} days"
 *     If is_expired is false and days > 30: green badge "Valid"
 *     SANs list (Subject Alternative Names) collapsed by default.
 *
 * EMPTY STATE:
 *   If httpFindings is empty:
 *   "No HTTP services found — no web services detected on this target."
 *
 * SECURITY HEADER LIST (hardcode these for the checkmark display):
 *   const ALL_HEADERS = [
 *     "Content-Security-Policy",
 *     "X-Frame-Options",
 *     "Strict-Transport-Security",
 *     "X-Content-Type-Options",
 *     "Referrer-Policy",
 *     "Permissions-Policy",
 *   ]
 *
 * SHADCN COMPONENTS USED:
 *   Card, CardHeader, CardContent, CardTitle
 *   Badge, Separator
 *
 * NOTE:
 *   No "use client" needed — purely display.
 *   If httpFindings has more than 5 items, show the first 3 expanded
 *   and the rest collapsed under a "Show {n} more" button.
 *   That button needs "use client".
 */