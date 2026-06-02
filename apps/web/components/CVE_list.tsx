/**
 * components/CVEList.tsx
 * ----------------------
 * Displays all CVEs found across the entire scan, deduplicated.
 * Shown in the "Vulnerabilities" tab of the results page.
 * This is the most important tab — leads with the scariest findings.
 *
 * PROPS:
 *   cves: CVEResult[]
 *     The top-level cves array from ScanReport (deduplicated, sorted
 *     by CVSS score descending by the backend).
 *   topFindings: CVEResult[]
 *     The top 5 CVEs identified by report_gen as most important.
 *
 * LAYOUT — two sections:
 *
 *   SECTION 1: "Critical Findings" (only shown if topFindings is not empty)
 *     Three horizontally arranged Cards, one per top finding (max 3 shown).
 *     Each card shows:
 *       - CVE ID in monospace font (e.g. CVE-2021-41773)
 *       - CVSS score large and colored
 *       - Severity badge
 *       - First 120 characters of the description
 *       - "View details →" link that opens the NVD page in a new tab
 *         URL: https://nvd.nist.gov/vuln/detail/{cve_id}
 *
 *   SECTION 2: "All Vulnerabilities"
 *     A scrollable list of ALL CVEs.
 *     Each row (use a Card or a bordered div):
 *       LEFT:  CVE ID + severity badge
 *       RIGHT: CVSS score circle (colored by severity)
 *       BELOW: description text (collapsed to 2 lines by default,
 *              expandable with a "Show more" toggle)
 *              + list of reference URLs (collapsed by default)
 *
 * FILTERING:
 *   Add four filter buttons above the list: All | Critical | High | Medium | Low
 *   Clicking a filter shows only CVEs of that severity.
 *   Track the active filter in local state (filter: string).
 *
 * CVSS SCORE CIRCLE:
 *   A small circle (48px) with the CVSS number inside.
 *   Background color matches severity:
 *     9.0+  → red
 *     7.0+  → orange
 *     4.0+  → yellow
 *     <4.0  → blue-gray
 *
 * EMPTY STATE:
 *   If cves is empty: "No vulnerabilities found — this target looks clean."
 *   Use a green checkmark icon (CheckCircle from lucide-react).
 *
 * SHADCN COMPONENTS USED:
 *   Card, CardContent, Badge, Button, ScrollArea
 *
 * NOTE:
 *   "use client" required for filter state and expand/collapse.
 *   Do not fetch any data here — all data comes via props from the results page.
 */