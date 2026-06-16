"use client"

import * as React from "react"
import Link from "next/link"
import { ArrowLeft } from "lucide-react"

import { getTargetHistory, type TargetHistory } from "@/lib/api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { RiskBadge } from "@/components/risk-badge"
import { RiskTrend } from "@/components/charts/risk-trend"
import { timeAgo } from "@/lib/format"

export default function TargetDetailPage({ params }: { params: Promise<{ target: string }> }) {
  const { target } = React.use(params)
  const decoded = decodeURIComponent(target)
  const [history, setHistory] = React.useState<TargetHistory | null>(null)
  const [loading, setLoading] = React.useState(true)

  React.useEffect(() => {
    getTargetHistory(decoded)
      .then(setHistory)
      .catch(() => setHistory(null))
      .finally(() => setLoading(false))
  }, [decoded])

  const completed = (history?.scans ?? []).filter((s) => s.status === "complete")
  const trend = [...completed]
    .reverse()
    .map((s) => ({
      label: s.started_at ? new Date(s.started_at).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "",
      risk: s.risk_score ?? 0,
    }))

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <Link href="/targets">
        <Button variant="ghost" size="sm">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Targets
        </Button>
      </Link>

      <div>
        <p className="text-xs font-medium uppercase tracking-[0.3em] text-primary">Target</p>
        <h1 className="font-heading font-mono text-2xl font-semibold">{decoded}</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Risk over time</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="grid h-56 place-items-center text-sm text-muted-foreground">Loading…</div>
          ) : (
            <RiskTrend data={trend} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Scan history</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {!history || history.scans.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-muted-foreground">No scans recorded.</p>
          ) : (
            <ul className="divide-y divide-border">
              {history.scans.map((s) => (
                <li key={s.scan_id}>
                  <Link
                    href={`/scan/${s.scan_id}`}
                    className="flex items-center justify-between gap-3 px-5 py-3 transition-colors hover:bg-muted/30"
                  >
                    <div>
                      <p className="text-sm">{timeAgo(s.started_at)}</p>
                      <p className="text-xs capitalize text-muted-foreground">{s.status}</p>
                    </div>
                    {s.status === "complete" ? (
                      <RiskBadge label={s.risk_label} score={s.risk_score} />
                    ) : (
                      <span className="text-xs capitalize text-muted-foreground">{s.status}</span>
                    )}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
