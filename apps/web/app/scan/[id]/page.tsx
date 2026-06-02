/**
 * app/scan/[id]/page.tsx
 * ----------------------
 * The results page. Shown after a scan is submitted.
 * Handles three states: scanning (in progress), complete, failed.
 *
 * URL PARAMETER:
 *   params.id — the scan_id UUID returned by POST /api/scans.
 *   Next.js passes this automatically from the [id] folder name.
 *
 * THIS MUST BE A CLIENT COMPONENT ("use client") because it polls
 * the API on an interval using useEffect and useState.
 *
 * STATE:
 *   status: "pending" | "running" | "complete" | "failed"
 *   report: ScanReport | null
 *   error: string | null
 *   currentModule: string | null   (which scanner module is running)
 *
 * BEHAVIOUR:
 *
 *   While status is "pending" or "running":
 *     Show the ScanProgress component.
 *     Every 3 seconds call getScanStatus(id) from lib/api.ts.
 *     Update currentModule from the response so the progress bar animates.
 *     When status becomes "complete": call getScanReport(id), store in state,
 *     clear the polling interval.
 *     When status becomes "failed": store the error, clear the interval.
 *
 *   IMPORTANT — clear the interval on component unmount:
 *     return () => clearInterval(intervalId)
 *     inside the useEffect cleanup. Without this, polling continues
 *     after the user navigates away and causes memory leaks.
 *
 *   When status is "complete":
 *     Show the full results dashboard:
 *       - RiskScore component (top, prominent)
 *       - Summary row: target, scan duration, modules run, open ports count
 *       - Tabs component with four tabs:
 *           "Vulnerabilities" → CVEList component
 *           "Open Ports"      → PortTable component
 *           "OSINT & DNS"     → OSINTPanel (inline, no separate file needed)
 *           "HTTP Findings"   → HttpPanel (inline, no separate file needed)
 *       - ReportExport component (bottom right)
 *
 *   When status is "failed":
 *     Show a red error card with the error message.
 *     Offer a "Try again" button that navigates back to homepage.
 *
 * SHADCN COMPONENTS USED:
 *   Tabs, TabsList, TabsTrigger, TabsContent
 *   Card, CardHeader, CardContent
 *   Badge, Separator
 *
 * POLLING INTERVAL: 3000ms (3 seconds).
 * Store the interval ID in a useRef, not useState, so updating it
 * does not trigger a re-render.
 */