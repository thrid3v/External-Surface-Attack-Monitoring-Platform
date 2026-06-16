/**
 * app/page.tsx
 * ------------
 * The homepage. First thing users see when they open the app.
 * Two responsibilities: accept a new scan target, show recent scan history.
 *
 * LAYOUT (top to bottom):
 *   1. Header bar — app name "EASM Scanner" + tagline
 *   2. ScanInput component — the main search box
 *   3. Recent scans list — last 20 scans from GET /api/scans
 *
 * BEHAVIOUR:
 *
 *   On load:
 *     Call getRecentScans() from lib/api.ts and display the results
 *     in a list below the search box. Show a Skeleton loader while
 *     the data is fetching. If the list is empty, show a friendly
 *     empty state: "No scans yet — enter a URL or IP above to get started."
 *
 *   When ScanInput submits:
 *     ScanInput calls startScan() and receives a scan_id back.
 *     Use Next.js router.push() to navigate to /scan/{scan_id}.
 *     The results page handles all polling and display from there.
 *     Pass an onScan callback prop to ScanInput for this navigation.
 *
 *   Recent scans list:
 *     Each item shows: target, risk_label badge, risk_score, time ago.
 *     Clicking a row navigates to /scan/{scan_id}.
 *     Use the Badge component for risk_label.
 *     Color the badge by severity:
 *       CRITICAL → destructive variant
 *       HIGH     → orange (custom class or inline style)
 *       MEDIUM   → warning yellow
 *       LOW      → secondary
 *       MINIMAL  → outline
 *
 * THIS IS A SERVER COMPONENT by default in Next.js App Router.
 * The recent scans fetch can happen server-side — no useEffect needed.
 * ScanInput must be a Client Component ("use client") because it handles
 * user interaction. Import it here and it works seamlessly.
 *
 * SHADCN COMPONENTS USED:
 *   Badge, Card, CardHeader, CardContent
 *
 * FILE SIZE TARGET: keep this under 80 lines.
 * It is a layout/composition file — all the real logic lives in components.
 */

import Link from "next/link"


import ScanInputClient from "@/components/scan_input_client"
import { Badge } from "@/components/ui/badge"
import { Card, CardHeader, CardContent } from "@/components/ui/card"
import { getRecentScansServer } from "@/lib/server-api"


function badgeVariant(label: string | null) {
  switch (label) {
    case "CRITICAL":
      return "destructive"
    case "LOW":
      return "secondary"
    case "MINIMAL":
      return "outline"
    default:
      return "outline"
  }
}

function badgeClass(label: string | null) {
  if (label === "HIGH") {
    return "border-orange-200 bg-orange-100 text-orange-900"
  }
  if (label === "MEDIUM") {
    return "border-amber-200 bg-amber-100 text-amber-950"
  }
  return undefined
}

function formatTimeAgo(value: string) {
  const diff = Date.now() - new Date(value).getTime()
  if (Number.isNaN(diff) || diff < 0) {
    return "Unknown"
  }

  const minutes = Math.floor(diff / 60000)
  if (minutes < 1) return "Just now"
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default async function Home() {
  const recentScans = await getRecentScansServer()

  return (
    <div className="flex min-h-screen flex-col items-center bg-zinc-50 px-6 py-10 font-sans dark:bg-black">
      <div className="w-full max-w-5xl space-y-8">
        <section className="space-y-3">
          <p className="text-sm uppercase tracking-[0.3em] text-muted-foreground">EASM Scanner</p>
          <h1 className="text-4xl font-semibold text-slate-950 dark:text-white">External surface attack monitoring</h1>
          <p className="max-w-2xl text-base text-slate-600 dark:text-slate-300">
            Scan URLs, domains, or IP addresses and review recent findings from your last scans.
          </p>
        </section>

        <Card className="rounded-3xl border border-border bg-card">
          <CardHeader className="gap-1 px-6 pt-6">
            <div>
              <p className="text-sm font-medium uppercase tracking-[0.2em] text-muted-foreground">New scan</p>
              <h2 className="text-2xl font-semibold text-slate-950 dark:text-white">Enter a target</h2>
            </div>
          </CardHeader>
          <CardContent className="px-6 pb-6 pt-4">
            <ScanInputClient />
          </CardContent>
        </Card>

        <section className="space-y-4">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <p className="text-sm font-medium uppercase tracking-[0.2em] text-muted-foreground">Recent scans</p>
              <h2 className="text-2xl font-semibold text-slate-950 dark:text-white">History</h2>
            </div>
          </div>

          {recentScans.length === 0 ? (
            <Card className="rounded-3xl border border-border bg-card">
              <CardContent className="space-y-2 text-center px-6 py-10">
                <p className="text-base font-semibold text-slate-950 dark:text-white">
                  No scans yet — enter a URL or IP above to get started.
                </p>
                <p className="text-sm text-muted-foreground">Scans will appear here once they are queued.</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-3">
              {recentScans.map((scan) => (
                <Link
                  key={scan.scan_id}
                  href={`/scan/${scan.scan_id}`}
                  className="group block rounded-3xl border border-border bg-card p-5 transition hover:border-primary/50 hover:bg-primary/5"
                >
                  <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                    <div className="space-y-1">
                      <p className="text-sm font-medium uppercase tracking-[0.15em] text-muted-foreground">{scan.target}</p>
                      <p className="text-base font-semibold text-slate-950 dark:text-white">{scan.target}</p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge
                        variant={badgeVariant(scan.risk_label)}
                        className={badgeClass(scan.risk_label)}
                      >
                        {scan.risk_label ?? "UNKNOWN"}
                      </Badge>                    
                      <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                        {scan.risk_score ?? "N/A"}
                      </span>
                      <span className="text-sm text-muted-foreground">{formatTimeAgo(scan.started_at)}</span>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
