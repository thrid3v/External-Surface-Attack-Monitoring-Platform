/**
 * components/PortTable.tsx
 * ------------------------
 * Renders the list of open ports found during the scan.
 * Shown in the "Open Ports" tab of the results page.
 *
 * PROPS:
 *   ports: PortResult[]
 *     The ports array from ScanReport. Each item has:
 *     port, protocol, state, service, product, version, banner, cves[]
 *
 * LAYOUT:
 *   shadcn Table with these columns:
 *     Port      | Protocol | Service    | Product + Version     | CVEs  | Risk
 *     --------- | -------- | ---------- | --------------------- | ----- | ----
 *     80        | tcp      | http       | Apache httpd 2.4.51   | 3     | HIGH
 *
 *   CVEs column:
 *     Show the count of CVEs on this port.
 *     Color the count by the highest severity CVE on that port:
 *       Any CRITICAL CVE → red badge
 *       Any HIGH CVE     → orange badge
 *       Any MEDIUM       → yellow badge
 *       Otherwise        → gray badge
 *
 *   Risk column:
 *     Badge showing the highest severity CVE label for this port.
 *     If no CVEs: show "None" in a gray outline badge.
 *
 *   Clicking a row:
 *     Expand it to show the full CVE list for that port inline.
 *     Use local state (expandedPort: number | null) to track which row
 *     is expanded. Clicking the same row again collapses it.
 *     In the expanded section, show each CVE as:
 *       CVE ID | CVSS Score | Severity | Description (truncated to 100 chars)
 *
 * SORTING:
 *   Default sort: by highest CVE severity descending (most dangerous first).
 *   If no CVEs on a port, sort by port number ascending.
 *
 * EMPTY STATE:
 *   If ports array is empty, show:
 *   "No open ports found" in a centered muted text inside the table area.
 *
 * SHADCN COMPONENTS USED:
 *   Table, TableHeader, TableRow, TableHead, TableBody, TableCell, Badge
 *
 * NOTE:
 *   "use client" is required because of the expand/collapse interaction.
 */