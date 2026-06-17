"use client"

import * as React from "react"
import { CheckCircle } from "lucide-react"

import { Badge } from "./ui/badge"
import { Button } from "./ui/button"
import { Card, CardContent } from "./ui/card"
import { cn } from "@/lib/utils"

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"

export interface CVEResult {
  cve_id: string
  description: string
  cvss_score: number | null
  cvss_version: string | null
  severity: Severity
  published_date: string | null
  references: string[]
}

interface CVEListProps {
  cves: CVEResult[]
  topFindings: CVEResult[]
}

const FILTERS = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const

function severityBadgeVariant(severity: Severity) {
  switch (severity) {
    case "CRITICAL":
      return "destructive"
    case "HIGH":
      return "secondary"
    case "MEDIUM":
      return "outline"
    case "LOW":
      return "default"
    default:
      return "ghost"
  }
}

function scoreCircleClass(cvssScore: number | null) {
  if (cvssScore === null) return "border border-border text-phosphor-dim"
  if (cvssScore >= 9) return "border border-red/50 text-red"
  if (cvssScore >= 7) return "border border-amber/50 text-amber"
  if (cvssScore >= 4) return "border border-yellow/50 text-yellow"
  return "border border-cyan/50 text-cyan"
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

function formatScore(score: number | null) {
  return score === null ? "N/A" : score.toFixed(1)
}

export function CVEList({ cves, topFindings }: CVEListProps) {
  const [filter, setFilter] = React.useState<(typeof FILTERS)[number]>("ALL")
  const [expanded, setExpanded] = React.useState<Record<string, boolean>>({})
  const [showReferences, setShowReferences] = React.useState<Record<string, boolean>>({})

  const filteredCves = React.useMemo(() => {
    if (filter === "ALL") {
      return cves
    }

    return cves.filter((cve) => cve.severity === filter)
  }, [cves, filter])

  if (!cves.length) {
    return (
      <Card className="rounded-3xl border border-border bg-card">
        <CardContent className="space-y-4 px-6 py-10 text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center border border-phosphor/40 bg-phosphor/5 text-phosphor">
            <CheckCircle className="h-8 w-8" />
          </div>
          <div className="space-y-2">
            <p className="font-display text-2xl text-phosphor-bright glow">no vulnerabilities found</p>
            <p className="text-sm text-phosphor-dim">no cves reported for this scan.</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-8">
      {topFindings.length > 0 ? (
        <section className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium uppercase tracking-[0.2em] text-muted-foreground">Critical Findings</p>
              <h2 className="text-2xl font-semibold">Top vulnerabilities</h2>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-3">
            {topFindings.slice(0, 3).map((finding) => (
              <Card key={finding.cve_id} className="rounded-3xl border border-border bg-card p-0">
                <CardContent className="space-y-4 px-6 py-6">
                  <div className="flex flex-col gap-2">
                    <span className="font-mono text-sm uppercase text-muted-foreground">{finding.cve_id}</span>
                    <div className="flex items-center gap-3">
                      <p className={cn("text-4xl font-semibold", scoreCircleClass(finding.cvss_score))}>{formatScore(finding.cvss_score)}</p>
                      <Badge variant={severityBadgeVariant(finding.severity)}>{severityLabel(finding.severity)}</Badge>
                    </div>
                  </div>

                  <p className="text-sm leading-6 text-muted-foreground">
                    {finding.description.slice(0, 120)}{finding.description.length > 120 ? "..." : ""}
                  </p>

                  <div>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-sm font-medium text-primary hover:underline"
                    >
                      View details →
                    </a>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>
      ) : null}

      <section className="space-y-4">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-sm font-medium uppercase tracking-[0.2em] text-muted-foreground">All Vulnerabilities</p>
            <h2 className="text-2xl font-semibold">Complete CVE list</h2>
          </div>
          <div className="flex flex-wrap gap-2">
            {FILTERS.map((value) => (
              <Button
                key={value}
                variant={filter === value ? "secondary" : "outline"}
                size="sm"
                onClick={() => setFilter(value)}
              >
                {value === "ALL" ? "All" : severityLabel(value as Severity)}
              </Button>
            ))}
          </div>
        </div>

        <div className="space-y-4 overflow-y-auto rounded-3xl border border-border bg-card p-4">
          {filteredCves.length === 0 ? (
            <Card className="rounded-3xl border border-border bg-card">
              <CardContent className="px-6 py-8 text-center">
                <p className="text-base font-semibold">No CVEs match the selected filter.</p>
                <p className="text-sm text-muted-foreground">Try a different severity to see more vulnerabilities.</p>
              </CardContent>
            </Card>
          ) : (
            filteredCves.map((cve) => {
              const isExpanded = expanded[cve.cve_id]
              const refsOpen = showReferences[cve.cve_id]

              return (
                <Card key={cve.cve_id} className="rounded-3xl border border-border bg-background">
                  <CardContent className="space-y-4 px-6 py-5">
                    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                      <div className="space-y-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-sm text-muted-foreground">{cve.cve_id}</span>
                          <Badge variant={severityBadgeVariant(cve.severity)}>{severityLabel(cve.severity)}</Badge>
                        </div>
                        <div className="text-sm text-muted-foreground">Published: {cve.published_date ?? "Unknown"}</div>
                      </div>

                      <div className={cn(
                        "flex h-12 min-w-[48px] items-center justify-center rounded-2xl px-4 text-sm font-semibold",
                        scoreCircleClass(cve.cvss_score)
                      )}>
                        {formatScore(cve.cvss_score)}
                      </div>
                    </div>

                    <div className="space-y-3">
                      <p
                        className={cn(
                          "text-sm leading-6 text-muted-foreground",
                          !isExpanded && "overflow-hidden text-ellipsis"
                        )}
                        style={
                          !isExpanded
                            ? {
                                display: "-webkit-box",
                                WebkitLineClamp: 2,
                                WebkitBoxOrient: "vertical",
                              }
                            : undefined
                        }
                      >
                        {cve.description}
                      </p>

                      <div className="flex flex-wrap items-center gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() =>
                            setExpanded((prev) => ({
                              ...prev,
                              [cve.cve_id]: !prev[cve.cve_id],
                            }))
                          }
                        >
                          {isExpanded ? "Show less" : "Show more"}
                        </Button>

                        {cve.references.length > 0 ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              setShowReferences((prev) => ({
                                ...prev,
                                [cve.cve_id]: !prev[cve.cve_id],
                              }))
                            }
                          >
                            {refsOpen ? "Hide references" : `Show references (${cve.references.length})`}
                          </Button>
                        ) : null}
                      </div>

                      {refsOpen && cve.references.length > 0 ? (
                        <div className="space-y-2 rounded-3xl border border-border bg-muted/40 p-4">
                          <p className="text-xs uppercase tracking-[0.2em] text-muted-foreground">References</p>
                          <ul className="space-y-2 text-sm">
                            {cve.references.map((href) => (
                              <li key={href}>
                                <a
                                  href={href}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="font-medium text-primary hover:underline"
                                >
                                  {href}
                                </a>
                              </li>
                            ))}
                          </ul>
                        </div>
                      ) : null}
                    </div>
                  </CardContent>
                </Card>
              )
            })
          )}
        </div>
      </section>
    </div>
  )
}