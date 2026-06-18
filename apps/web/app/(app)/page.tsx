import Link from "next/link"

import { getRecentScansServer, getTargetsServer, getAlertsServer } from "@/lib/server-api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import ScanInputClient from "@/components/scan_input_client"
import { RiskBadge } from "@/components/risk-badge"
import { SeverityDonut } from "@/components/charts/severity-donut"
import { severityColor } from "@/lib/severity"
import { timeAgo } from "@/lib/format"

export const dynamic = "force-dynamic"

const RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]

function Readout({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="px-4 py-3">
      <p className="text-[10px] uppercase tracking-[0.2em] text-phosphor-dim">{label}</p>
      <div className="mt-0.5 font-display text-3xl leading-none tabular-nums">{value}</div>
    </div>
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
      <header className="border-b border-border pb-3">
        <h1 className="font-display text-3xl leading-none text-phosphor-bright glow">{"// overview"}</h1>
        <p className="mt-1 text-xs text-phosphor-dim">external attack surface — at a glance</p>
      </header>

      {/* scan command */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">❯ new scan</CardTitle>
        </CardHeader>
        <CardContent>
          <ScanInputClient />
        </CardContent>
      </Card>

      {/* readout strip */}
      <Card className="py-0">
        <div className="grid grid-cols-2 divide-x divide-y divide-border sm:grid-cols-4 sm:divide-y-0">
          <Readout
            label="highest_risk"
            value={
              highest ? (
                <span className={severityColor(highest.risk_label).text + " glow"}>
                  {highest.risk_score ?? "—"}
                </span>
              ) : (
                <span className="text-phosphor-dim">—</span>
              )
            }
          />
          <Readout label="targets" value={<span className="text-phosphor">{targets.length}</span>} />
          <Readout label="recent_scans" value={<span className="text-phosphor">{scans.length}</span>} />
          <Readout
            label="unread_alerts"
            value={<span className={unread.length ? "text-amber glow" : "text-phosphor-dim"}>{unread.length}</span>}
          />
        </div>
      </Card>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* distribution */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-base">targets by risk</CardTitle>
          </CardHeader>
          <CardContent>
            <SeverityDonut data={distribution} label="targets" />
            <div className="mt-4 space-y-1 text-xs">
              {distribution.map((d) => (
                <div key={d.name} className="flex items-center justify-between border border-border px-2.5 py-1">
                  <span className="flex items-center gap-2">
                    <span className={`h-2 w-2 ${severityColor(d.name).dot}`} />
                    <span className={severityColor(d.name).text}>{d.name}</span>
                  </span>
                  <span className="tabular-nums text-phosphor">{String(d.value).padStart(2, "0")}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* recent scans */}
        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle className="text-base">recent scans</CardTitle>
            <Link href="/targets" className="text-xs text-cyan hover:underline">
              all targets →
            </Link>
          </CardHeader>
          <CardContent>
            {scans.length === 0 ? (
              <p className="py-8 text-center text-sm text-phosphor-dim">
                no scans yet — run one above.
              </p>
            ) : (
              <ul>
                {scans.slice(0, 8).map((s) => (
                  <li key={s.scan_id}>
                    <Link
                      href={`/scan/${s.scan_id}`}
                      className="group flex items-center justify-between gap-3 border-b border-border/50 py-2 transition-colors last:border-0 hover:bg-accent"
                    >
                      <span className="flex min-w-0 items-center gap-2">
                        <span className="text-phosphor-dim group-hover:text-phosphor-bright">▸</span>
                        <span className="truncate text-phosphor">{s.target}</span>
                        <span className="shrink-0 text-xs text-phosphor-dim/60">{timeAgo(s.started_at)}</span>
                      </span>
                      {s.status === "complete" ? (
                        <RiskBadge label={s.risk_label} score={s.risk_score} />
                      ) : (
                        <span className="border border-border px-1.5 text-[11px] uppercase tracking-wider text-phosphor-dim">
                          {s.status}
                        </span>
                      )}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      {/* latest alerts */}
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle className="text-base">latest alerts</CardTitle>
          <Link href="/alerts" className="text-xs text-cyan hover:underline">
            view all →
          </Link>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <p className="py-6 text-center text-sm text-phosphor-dim">
              no alerts. re-scans flag new risk here.
            </p>
          ) : (
            <ul className="space-y-1">
              {alerts.slice(0, 5).map((a) => (
                <li key={a.id} className="flex items-center gap-3 border border-border px-3 py-2 text-sm">
                  <span className={`h-2 w-2 shrink-0 ${severityColor(a.severity).dot}`} />
                  <span className="flex-1 text-phosphor">{a.message}</span>
                  <span className="shrink-0 text-xs text-phosphor-dim/60">{timeAgo(a.created_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
