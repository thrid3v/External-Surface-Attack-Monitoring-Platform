"use client"

import * as React from "react"

import { Badge } from "./ui/badge"
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "./ui/table"

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"

export interface CVEResult {
  cve_id: string
  description: string
  cvss_score: number | null
  cvss_version: string | null
  severity: Severity
  published_date: string | null
  references: string[]
}

export interface PortResult {
  port: number
  protocol: string
  service: string | null 
  product?: string | null
  version?: string | null
  banner?: string | null
  cves?: CVEResult[]
}

const severityRank: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  NONE: 4,
}

function getHighestSeverity(cves: CVEResult[] | undefined): Severity {
  if (!cves?.length) {
    return "NONE"
  }

  return cves.reduce<Severity>((highest, cve) => {
    const currentRank = severityRank[cve.severity] ?? severityRank.NONE
    const highestRank = severityRank[highest] ?? severityRank.NONE
    return currentRank < highestRank ? cve.severity : highest
  }, "NONE")
}

function severityLabel(severity: Severity) {
  switch (severity) {
    case "CRITICAL":
      return "Critical"
    case "HIGH":
      return "High"
    case "MEDIUM":
      return "Medium"
    case "LOW":
      return "Low"
    case "NONE":
      return "None"
    default:
      return "Unknown"
  }
}

function cveCountBadgeProps(severity: Severity) {
  switch (severity) {
    case "CRITICAL":
      return { variant: "destructive" as const }
    case "HIGH":
      return { variant: "outline" as const, className: "border-amber/50 text-amber" }
    case "MEDIUM":
      return { variant: "outline" as const, className: "border-yellow/50 text-yellow" }
    default:
      return { variant: "outline" as const, className: "border-border text-phosphor-dim" }
  }
}

function riskBadgeProps(severity: Severity) {
  switch (severity) {
    case "CRITICAL":
      return { variant: "destructive" as const }
    case "HIGH":
      return { variant: "secondary" as const }
    case "MEDIUM":
      return { variant: "outline" as const, className: "border-amber-200 text-amber-950" }
    case "LOW":
      return { variant: "default" as const }
    default:
      return { variant: "outline" as const }
  }
}

export default function PortTable({ ports }: { ports: PortResult[] }) {
  const [expandedPort, setExpandedPort] = React.useState<number | null>(null)

  const sortedPorts = React.useMemo(() => {
    return [...ports].sort((a, b) => {
      const severityA = getHighestSeverity(a.cves)
      const severityB = getHighestSeverity(b.cves)
      const rankA = severityRank[severityA]
      const rankB = severityRank[severityB]

      if (rankA !== rankB) {
        return rankA - rankB
      }

      return Number(a.port) - Number(b.port)
    })
  }, [ports])

  const togglePort = (port: number) => {
    setExpandedPort((current) => (current === port ? null : port))
  }

  if (!ports.length) {
    return (
      <div className="rounded-3xl border border-border bg-card px-6 py-16 text-center text-sm text-muted-foreground">
        No open ports found
      </div>
    )
  }

  return (
    <Table className="bg-card rounded-3xl border border-border">
      <TableHeader>
        <TableRow>
          <TableHead>Port</TableHead>
          <TableHead>Protocol</TableHead>
          <TableHead>Service</TableHead>
          <TableHead>Product + Version</TableHead>
          <TableHead>CVEs</TableHead>
          <TableHead>Risk</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {sortedPorts.map((portResult) => {
          const portValue = Number(portResult.port)
          const cves = portResult.cves ?? []
          const highestSeverity = getHighestSeverity(cves)
          const countBadge = cveCountBadgeProps(highestSeverity)
          const riskBadge = riskBadgeProps(highestSeverity)
          const expanded = expandedPort === portValue
          const productVersion = [portResult.product, portResult.version].filter(Boolean).join(" ") || "-"

          return (
            <React.Fragment key={`${portValue}-${portResult.protocol}-${portResult.service}`}>
              <TableRow
                className="cursor-pointer"
                aria-expanded={expanded}
                onClick={() => togglePort(portValue)}
              >
                <TableCell>{portValue}</TableCell>
                <TableCell>{portResult.protocol}</TableCell>
                <TableCell>{portResult.service || "-"}</TableCell>
                <TableCell>{productVersion}</TableCell>
                <TableCell>
                  <Badge className="min-w-[2rem] justify-center" {...countBadge}>
                    {cves.length}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge className="min-w-[4rem] justify-center" {...riskBadge}>
                    {severityLabel(highestSeverity)}
                  </Badge>
                </TableCell>
              </TableRow>

              {expanded ? (
                <TableRow className="bg-bg-inset">
                  <TableCell colSpan={6} className="p-0">
                    <div className="border-t border-border bg-background px-4 py-4">
                      <div className="grid grid-cols-[1.4fr_80px_96px_1fr] gap-3 px-2 pb-3 text-xs uppercase tracking-[0.12em] text-muted-foreground">
                        <span>CVE ID</span>
                        <span>CVSS Score</span>
                        <span>Severity</span>
                        <span>Description</span>
                      </div>
                      {cves.length ? (
                        <div className="space-y-2">
                          {cves.map((cve) => (
                            <div
                              key={cve.cve_id}
                              className="grid grid-cols-[1.4fr_80px_96px_1fr] gap-3 rounded-2xl border border-border bg-muted/50 px-3 py-3 text-sm"
                            >
                              <span className="font-mono text-sm text-foreground">{cve.cve_id}</span>
                              <span>{cve.cvss_score === null ? "N/A" : cve.cvss_score.toFixed(1)}</span>
                              <Badge className="self-start" {...riskBadgeProps(cve.severity)}>
                                {severityLabel(cve.severity)}
                              </Badge>
                              <span className="text-sm text-muted-foreground">
                                {cve.description.length > 100
                                  ? `${cve.description.slice(0, 100).trimEnd()}…`
                                  : cve.description}
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="border border-border bg-bg-inset px-4 py-6 text-center text-sm text-phosphor-dim">
                          no cves found for this port.
                        </div>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ) : null}
            </React.Fragment>
          )
        })}
      </TableBody>
    </Table>
  )
}
