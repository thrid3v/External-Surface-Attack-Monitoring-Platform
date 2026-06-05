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

"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Clock, AlertCircle, ArrowLeft } from "lucide-react"

import { getScanStatus, getScanReport } from "@/lib/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import ScanProgress from "@/components/scan_progress"
import RiskScore from "@/components/risk_score"
import { CVEList } from "@/components/CVE_list"
import PortTable from "@/components/port_table"
import HttpPanel from "@/components/HTTP_panel"
import ReportExport from "@/components/report_export"

const POLLING_INTERVAL = 3000 // 3 seconds

interface PageProps {
  params: {
    id: string
  }
}

export default function ResultsPage({ params }: PageProps) {
  const router = useRouter()
  const [status, setStatus] = React.useState<"pending" | "running" | "complete" | "failed">(
    "pending"
  )
  const [report, setReport] = React.useState<any>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [currentModule, setCurrentModule] = React.useState<string | null>(null)

  const intervalRef = React.useRef<NodeJS.Timeout | null>(null)

  // Start polling for scan status
  React.useEffect(() => {
    const poll = async () => {
      try {
        const statusResponse = await getScanStatus(params.id)

        if (statusResponse.status === "complete") {
          // Scan is done, fetch the full report
          try {
            const reportData = await getScanReport(params.id)
            setReport(reportData)
            setStatus("complete")

            // Clear the interval
            if (intervalRef.current) {
              clearInterval(intervalRef.current)
              intervalRef.current = null
            }
          } catch (err) {
            setError(`Failed to fetch report: ${err instanceof Error ? err.message : "Unknown error"}`)
            setStatus("failed")

            if (intervalRef.current) {
              clearInterval(intervalRef.current)
              intervalRef.current = null
            }
          }
        } else if (statusResponse.status === "failed") {
          setError(
            (statusResponse as any).error || "Scan failed without a specific error message"
          )
          setStatus("failed")

          if (intervalRef.current) {
            clearInterval(intervalRef.current)
            intervalRef.current = null
          }
        } else {
          // Still pending or running
          setStatus(statusResponse.status as "pending" | "running")
          setCurrentModule(statusResponse.current_module || null)
        }
      } catch (err) {
        // Connection error, but keep polling
        // eslint-disable-next-line no-console
        console.error("Polling error:", err)
      }
    }

    // Do an initial poll immediately
    poll()

    // Then set up the interval
    intervalRef.current = setInterval(poll, POLLING_INTERVAL)

    // Cleanup on unmount
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }
  }, [params.id])

  // Render pending/running state
  if (status === "pending" || status === "running") {
    return (
      <div className="min-h-screen bg-background p-4 sm:p-6">
        <div className="mx-auto max-w-2xl">
          <Link href="/">
            <Button variant="ghost" size="sm" className="mb-6">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
          </Link>
          <ScanProgress currentModule={currentModule} target={params.id} />
        </div>
      </div>
    )
  }

  // Render failed state
  if (status === "failed") {
    return (
      <div className="min-h-screen bg-background p-4 sm:p-6">
        <div className="mx-auto max-w-2xl">
          <Link href="/">
            <Button variant="ghost" size="sm" className="mb-6">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
          </Link>

          <Card className="rounded-3xl border border-destructive bg-destructive/5">
            <CardHeader className="flex flex-row items-start gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-destructive/10">
                <AlertCircle className="h-6 w-6 text-destructive" />
              </div>
              <div>
                <CardTitle>Scan Failed</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-foreground">{error}</p>
              <Button onClick={() => router.push("/")} variant="default">
                Try Again
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    )
  }

  // Render complete state with results
  if (!report) {
    return null
  }

  const target = report.target || "Unknown"
  const riskScore = report.risk_score ?? 0
  const riskLabel = report.risk_label ?? "UNKNOWN"
  const cves = report.cves ?? []
  const ports = report.ports ?? []
  const osintData = report.osint ?? {}
  const httpFindings = report.http_findings ?? []
  const dnsRecords = report.dns_records ?? {}

  // Calculate severity summary
  const severitySummary = {
    critical: cves.filter((c: any) => c.severity === "CRITICAL").length,
    high: cves.filter((c: any) => c.severity === "HIGH").length,
    medium: cves.filter((c: any) => c.severity === "MEDIUM").length,
    low: cves.filter((c: any) => c.severity === "LOW").length,
  }

  // Get top findings for CVEList
  const topFindings = cves
    .sort((a: any, b: any) => {
      const severityRank: Record<string, number> = {
        CRITICAL: 0,
        HIGH: 1,
        MEDIUM: 2,
        LOW: 3,
      }
      const rankA = severityRank[a.severity] ?? 999
      const rankB = severityRank[b.severity] ?? 999
      if (rankA !== rankB) return rankA - rankB
      return (b.cvss_score ?? 0) - (a.cvss_score ?? 0)
    })
    .slice(0, 3)

  // Calculate duration
  const startedAt = report.started_at ? new Date(report.started_at) : null
  const completedAt = report.completed_at ? new Date(report.completed_at) : null
  const duration =
    startedAt && completedAt ? Math.round((completedAt.getTime() - startedAt.getTime()) / 1000) : null

  return (
    <div className="min-h-screen bg-background p-4 sm:p-6">
      <div className="mx-auto max-w-7xl space-y-6">
        <div className="flex items-center justify-between gap-4">
          <Link href="/">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Button>
          </Link>

          <ReportExport report={report} target={target} />
        </div>

        {/* Risk Score Component */}
        <RiskScore score={riskScore} label={riskLabel} severitySummary={severitySummary} target={target} />

        {/* Summary Row */}
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card className="rounded-3xl border border-border">
            <CardContent className="space-y-2 pt-6">
              <p className="text-sm text-muted-foreground">Target</p>
              <p className="font-mono text-sm font-medium">{target}</p>
            </CardContent>
          </Card>

          {duration ? (
            <Card className="rounded-3xl border border-border">
              <CardContent className="space-y-2 pt-6">
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">Duration</p>
                </div>
                <p className="text-sm font-medium">
                  {duration < 60 ? `${duration}s` : `${Math.round(duration / 60)}m ${duration % 60}s`}
                </p>
              </CardContent>
            </Card>
          ) : null}

          <Card className="rounded-3xl border border-border">
            <CardContent className="space-y-2 pt-6">
              <p className="text-sm text-muted-foreground">Open Ports</p>
              <p className="text-sm font-medium">{ports.length}</p>
            </CardContent>
          </Card>

          <Card className="rounded-3xl border border-border">
            <CardContent className="space-y-2 pt-6">
              <p className="text-sm text-muted-foreground">Vulnerabilities</p>
              <p className="text-sm font-medium">{cves.length}</p>
            </CardContent>
          </Card>
        </div>

        {/* Tabs */}
        <Tabs defaultValue="vulnerabilities" className="space-y-4">
          <TabsList className="flex w-full gap-1 rounded-3xl border border-border bg-background p-2">
            <TabsTrigger value="vulnerabilities" className="flex-1">
              Vulnerabilities
            </TabsTrigger>
            <TabsTrigger value="ports" className="flex-1">
              Open Ports
            </TabsTrigger>
            <TabsTrigger value="osint" className="flex-1">
              OSINT & DNS
            </TabsTrigger>
            <TabsTrigger value="http" className="flex-1">
              HTTP Findings
            </TabsTrigger>
          </TabsList>

          <TabsContent value="vulnerabilities">
            <CVEList cves={cves} topFindings={topFindings} />
          </TabsContent>

          <TabsContent value="ports">
            <PortTable ports={ports} />
          </TabsContent>

          <TabsContent value="osint" className="space-y-4">
            {/* Placeholder for OSINTPanel - inline implementation */}
            <Card className="rounded-3xl border border-border">
              <CardHeader>
                <CardTitle>OSINT & DNS Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                {osintData.whois ? (
                  <div className="space-y-2">
                    <h3 className="font-semibold">WHOIS</h3>
                    <pre className="overflow-auto rounded-2xl border border-border bg-muted p-4 text-xs text-foreground">
                      {typeof osintData.whois === "string"
                        ? osintData.whois
                        : JSON.stringify(osintData.whois, null, 2)}
                    </pre>
                  </div>
                ) : null}

                {dnsRecords && Object.keys(dnsRecords).length > 0 ? (
                  <div className="space-y-2">
                    <h3 className="font-semibold">DNS Records</h3>
                    <div className="space-y-2">
                      {Object.entries(dnsRecords).map(([key, value]) => (
                        <div key={key} className="rounded-2xl border border-border bg-muted p-3">
                          <p className="text-xs text-muted-foreground">{key}</p>
                          <p className="text-sm font-mono">
                            {Array.isArray(value) ? value.join(", ") : String(value)}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No DNS data available</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="http">
            <HttpPanel httpFindings={httpFindings} />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}
