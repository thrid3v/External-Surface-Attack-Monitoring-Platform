"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Clock, AlertCircle, ArrowLeft, ShieldAlert } from "lucide-react"

import { getScanStatus, getScanReport, getScanDiff } from "@/lib/api"
import type { ScanReport, CVEResult, DiffResult } from "@/lib/types"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import ScanProgress from "@/components/scan_progress"
import RiskScore from "@/components/risk_score"
import { CVEList } from "@/components/CVE_list"
import PortTable from "@/components/port_table"
import HttpPanel from "@/components/HTTP_panel"
import OSINTPanel from "@/components/OSINT_panel"
import ReportExport from "@/components/report_export"
import { DiffPanel } from "@/components/diff_panel"
import { formatDuration } from "@/lib/format"

const POLLING_INTERVAL = 3000

interface PageProps {
  params: Promise<{ id: string }>
}

function Stat({ label, value, icon: Icon }: { label: string; value: React.ReactNode; icon?: React.ElementType }) {
  return (
    <Card>
      <CardContent className="space-y-1 pt-6">
        <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
          {Icon ? <Icon className="h-3.5 w-3.5" /> : null}
          {label}
        </div>
        <div className="font-mono text-sm font-medium">{value}</div>
      </CardContent>
    </Card>
  )
}

export default function ResultsPage({ params }: PageProps) {
  const { id } = React.use(params)
  const router = useRouter()
  const [status, setStatus] = React.useState<"pending" | "running" | "complete" | "failed">("pending")
  const [report, setReport] = React.useState<ScanReport | null>(null)
  const [diff, setDiff] = React.useState<DiffResult | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [currentModule, setCurrentModule] = React.useState<string | null>(null)
  const intervalRef = React.useRef<NodeJS.Timeout | null>(null)

  React.useEffect(() => {
    const stop = () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }
    const poll = async () => {
      try {
        const s = await getScanStatus(id)
        if (s.status === "complete") {
          stop()
          try {
            const data = await getScanReport(id)
            setReport(data)
            setStatus("complete")
            getScanDiff(id).then(setDiff).catch(() => setDiff(null))
          } catch (err) {
            setError(`Failed to fetch report: ${err instanceof Error ? err.message : "Unknown error"}`)
            setStatus("failed")
          }
        } else if (s.status === "failed") {
          stop()
          setError(s.error || "Scan failed without a specific error message")
          setStatus("failed")
        } else {
          setStatus(s.status as "pending" | "running")
          setCurrentModule(s.current_module || null)
        }
      } catch (err) {
        console.error("Polling error:", err)
      }
    }
    poll()
    intervalRef.current = setInterval(poll, POLLING_INTERVAL)
    return stop
  }, [id])

  if (status === "pending" || status === "running") {
    return (
      <div className="mx-auto max-w-2xl">
        <Link href="/">
          <Button variant="ghost" size="sm" className="mb-6">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back
          </Button>
        </Link>
        <ScanProgress currentModule={currentModule} target={id} />
      </div>
    )
  }

  if (status === "failed") {
    return (
      <div className="mx-auto max-w-2xl">
        <Link href="/">
          <Button variant="ghost" size="sm" className="mb-6">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back
          </Button>
        </Link>
        <Card className="border-destructive/40 bg-destructive/5">
          <CardHeader className="flex-row items-center gap-4">
            <span className="grid h-12 w-12 place-items-center rounded-2xl bg-destructive/10">
              <AlertCircle className="h-6 w-6 text-destructive" />
            </span>
            <CardTitle>Scan failed</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-foreground">{error}</p>
            <Button onClick={() => router.push("/")}>Try again</Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!report) return null

  const target = report.target || "Unknown"
  const riskScore = report.risk_score ?? 0
  const riskLabel = report.risk_label ?? "UNKNOWN"
  const cves = report.cves ?? []
  const ports = report.ports ?? []
  const osintData = report.osint ?? {}
  const httpFindings = report.http_findings ?? []
  const dnsRecords = report.dns_records ?? []
  const subdomains = report.subdomains ?? []

  const severitySummary = {
    critical: cves.filter((c) => c.severity === "CRITICAL").length,
    high: cves.filter((c) => c.severity === "HIGH").length,
    medium: cves.filter((c) => c.severity === "MEDIUM").length,
    low: cves.filter((c) => c.severity === "LOW").length,
  }

  const topFindings = [...cves]
    .sort((a: CVEResult, b: CVEResult) => {
      const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
      const ra = rank[a.severity] ?? 999
      const rb = rank[b.severity] ?? 999
      if (ra !== rb) return ra - rb
      return (b.cvss_score ?? 0) - (a.cvss_score ?? 0)
    })
    .slice(0, 3)

  return (
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

      {report.zone_transfer_vulnerable ? (
        <Card className="border-red-500/40 bg-red-500/5">
          <CardContent className="flex items-start gap-3 pt-6">
            <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-red-400" />
            <div>
              <p className="font-semibold text-red-400">DNS zone transfer exposed</p>
              <p className="text-sm text-muted-foreground">
                An authoritative name server allowed an AXFR transfer, leaking{" "}
                {report.zone_transfer_records?.length ?? 0} internal DNS records. This is a high-severity
                misconfiguration — restrict zone transfers to trusted secondaries.
              </p>
            </div>
          </CardContent>
        </Card>
      ) : null}

      <RiskScore score={riskScore} label={riskLabel} severitySummary={severitySummary} target={target} />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Target" value={target} />
        <Stat label="Duration" value={formatDuration(report.scan_duration_seconds)} icon={Clock} />
        <Stat label="Open ports" value={ports.length} />
        <Stat label="Vulnerabilities" value={cves.length} />
      </div>

      {diff ? <DiffPanel diff={diff} /> : null}

      <Tabs defaultValue="vulnerabilities" className="space-y-4">
        <TabsList className="flex w-full gap-1 rounded-2xl border border-border bg-card p-1.5">
          <TabsTrigger value="vulnerabilities" className="flex-1">
            Vulnerabilities
          </TabsTrigger>
          <TabsTrigger value="ports" className="flex-1">
            Open Ports
          </TabsTrigger>
          <TabsTrigger value="osint" className="flex-1">
            OSINT &amp; DNS
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
        <TabsContent value="osint">
          <OSINTPanel osint={osintData} dnsRecords={dnsRecords} subdomains={subdomains} />
        </TabsContent>
        <TabsContent value="http">
          <HttpPanel httpFindings={httpFindings} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
