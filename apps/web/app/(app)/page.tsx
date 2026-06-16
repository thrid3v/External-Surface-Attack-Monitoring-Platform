import Link from "next/link"
import { Crosshair, Radar, Bell, Gauge, ArrowRight } from "lucide-react"

import { getRecentScansServer, getTargetsServer, getAlertsServer } from "@/lib/server-api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import ScanInputClient from "@/components/scan_input_client"
import { RiskBadge } from "@/components/risk-badge"
import { SeverityDonut } from "@/components/charts/severity-donut"
import { severityColor } from "@/lib/severity"
import { timeAgo } from "@/lib/format"

export const dynamic = "force-dynamic"

const RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]

function StatCard({
  icon: Icon,
  label,
  value,
  accent,
}: {
  icon: React.ElementType
  label: string
  value: React.ReactNode
  accent?: string
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 pt-6">
        <span className={`grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary ${accent ?? ""}`}>
          <Icon className="h-5 w-5" />
        </span>
        <div className="min-w-0">
          <p className="text-xs uppercase tracking-wider text-muted-foreground">{label}</p>
          <div className="text-2xl font-semibold tabular-nums">{value}</div>
        </div>
      </CardContent>
    </Card>
  )
}

export default async function DashboardPage() {
  const [scans, targets, alerts] = await Promise.all([
    getRecentScansServer(),
    getTargetsServer(),
    getAlertsServer(),
  ])

  const unread = alerts.filter((a) => !a.read)
  const highest = [...scans].sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))[0]
  const distribution = RISK_LEVELS.map((name) => ({
    name,
    value: targets.filter((t) => (t.last_risk_label ?? "MINIMAL").toUpperCase() === name).length,
  }))

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div>
        <p className="text-xs font-medium uppercase tracking-[0.3em] text-primary">Attack Surface</p>
        <h1 className="font-heading text-2xl font-semibold">Overview</h1>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm uppercase tracking-wider text-muted-foreground">New scan</CardTitle>
        </CardHeader>
        <CardContent>
          <ScanInputClient />
        </CardContent>
      </Card>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          icon={Gauge}
          label="Highest risk"
          value={
            highest ? (
              <span className={severityColor(highest.risk_label).text}>{highest.risk_score ?? "—"}</span>
            ) : (
              "—"
            )
          }
        />
        <StatCard icon={Crosshair} label="Targets" value={targets.length} />
        <StatCard icon={Radar} label="Recent scans" value={scans.length} />
        <StatCard
          icon={Bell}
          label="Unread alerts"
          value={<span className={unread.length ? "text-orange-400" : ""}>{unread.length}</span>}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Targets by risk</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityDonut data={distribution} label="targets" />
            <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
              {distribution.map((d) => (
                <div key={d.name} className="flex items-center justify-between rounded-lg bg-muted/40 px-2.5 py-1.5">
                  <span className="flex items-center gap-2">
                    <span className={`h-2 w-2 rounded-full ${severityColor(d.name).dot}`} />
                    {d.name}
                  </span>
                  <span className="font-semibold tabular-nums">{d.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Recent scans</CardTitle>
            <Link href="/targets" className="text-xs text-primary hover:underline">
              All targets
            </Link>
          </CardHeader>
          <CardContent>
            {scans.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No scans yet — start one above.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {scans.slice(0, 8).map((s) => (
                  <li key={s.scan_id}>
                    <Link
                      href={`/scan/${s.scan_id}`}
                      className="group flex items-center justify-between gap-3 py-3 transition-colors hover:bg-muted/30"
                    >
                      <div className="min-w-0">
                        <p className="truncate font-mono text-sm">{s.target}</p>
                        <p className="text-xs text-muted-foreground">{timeAgo(s.started_at)}</p>
                      </div>
                      <div className="flex items-center gap-3">
                        {s.status === "complete" ? (
                          <RiskBadge label={s.risk_label} score={s.risk_score} />
                        ) : (
                          <span className="rounded-full border border-border px-2.5 py-0.5 text-xs capitalize text-muted-foreground">
                            {s.status}
                          </span>
                        )}
                        <ArrowRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
                      </div>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>Latest alerts</CardTitle>
          <Link href="/alerts" className="text-xs text-primary hover:underline">
            View all
          </Link>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">No alerts. Re-scans will flag new risk here.</p>
          ) : (
            <ul className="space-y-2">
              {alerts.slice(0, 5).map((a) => (
                <li
                  key={a.id}
                  className="flex items-center gap-3 rounded-xl border border-border px-3 py-2.5 text-sm"
                >
                  <span className={`h-2 w-2 shrink-0 rounded-full ${severityColor(a.severity).dot}`} />
                  <span className="flex-1">{a.message}</span>
                  <span className="shrink-0 text-xs text-muted-foreground">{timeAgo(a.created_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
