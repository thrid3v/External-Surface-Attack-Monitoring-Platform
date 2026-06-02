/**
 * lib/api.ts
 * ----------
 * Typed fetch wrapper for all communication with the FastAPI backend.
 * Every component that needs data imports functions from here.
 * No component ever calls fetch() directly — all API logic lives here.
 *
 * BASE URL:
 *   Read from environment variable NEXT_PUBLIC_API_URL.
 *   In development this is http://localhost:8000
 *   In production it is your deployed API URL.
 *   Next.js exposes env vars prefixed with NEXT_PUBLIC_ to the browser.
 *
 * CONTAINS:
 *
 *   Types (mirror your Pydantic models from scanner_core/models.py):
 *   ---------------------------------------------------------------
 *   interface PortResult {
 *     port: number
 *     protocol: string
 *     state: string
 *     service: string | null
 *     product: string | null
 *     version: string | null
 *     banner: string | null
 *     cves: CVEResult[]
 *   }
 *
 *   interface CVEResult {
 *     cve_id: string
 *     description: string
 *     cvss_score: number | null
 *     cvss_version: string | null
 *     severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
 *     published_date: string | null
 *     references: string[]
 *   }
 *
 *   interface ScanStatus {
 *     scan_id: string
 *     status: "pending" | "running" | "complete" | "failed"
 *     current_module: string | null
 *     modules_complete: string[]
 *     started_at: string | null
 *   }
 *
 *   interface ScanReport {
 *     scan_id: string
 *     target: string
 *     status: string
 *     risk_score: number | null
 *     risk_label: string | null
 *     severity_summary: Record<string, number>
 *     ports: PortResult[]
 *     cves: CVEResult[]
 *     dns_records: DNSRecord[]
 *     subdomains: SubdomainResult[]
 *     osint: OSINTResult | null
 *     http_findings: HttpFinding[]
 *     top_findings: CVEResult[]
 *     started_at: string | null
 *     completed_at: string | null
 *     scan_duration_seconds: number | null
 *     modules_run: string[]
 *     errors: Record<string, string>
 *   }
 *
 *   interface RecentScan {
 *     scan_id: string
 *     target: string
 *     status: string
 *     risk_score: number | null
 *     risk_label: string | null
 *     started_at: string
 *   }
 *
 *   API functions:
 *   -------------
 *   startScan(target: string, portRange?: string): Promise<{ scan_id: string, status: string }>
 *     Calls POST /api/scans.
 *     Sends { target, port_range, i_own_this_target: true }.
 *     Returns the scan_id to use for polling.
 *     Throws an Error with a readable message if the API returns 4xx/5xx.
 *
 *   getScanStatus(scanId: string): Promise<ScanStatus>
 *     Calls GET /api/scans/{scanId}/status.
 *     Used by ScanProgress.tsx during polling.
 *     Returns status + current_module so the progress bar can update.
 *
 *   getScanReport(scanId: string): Promise<ScanReport>
 *     Calls GET /api/scans/{scanId}.
 *     Used by the results page after status becomes "complete".
 *     Returns the full ScanReport.
 *
 *   getRecentScans(): Promise<RecentScan[]>
 *     Calls GET /api/scans.
 *     Returns last 20 scans for the homepage history list.
 *
 *   HELPER:
 *   async function apiFetch<T>(path: string, options?: RequestInit): Promise<T>
 *     Private base function used by all the above.
 *     Prepends BASE_URL, sets Content-Type: application/json header.
 *     On non-ok response: reads the error body and throws a descriptive Error.
 *     All public functions call this — never call fetch() directly elsewhere.
 *
 * ERROR HANDLING PATTERN:
 *   All functions throw on failure so components can catch and display errors.
 *   The error message should be human-readable e.g.:
 *     "Scan not found" (404)
 *     "You must confirm you own this target" (403)
 *     "Server error, please try again" (500)
 */