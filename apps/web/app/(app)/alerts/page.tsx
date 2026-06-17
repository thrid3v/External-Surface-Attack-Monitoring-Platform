"use client"

import * as React from "react"

import { listAlerts, markAlertRead, markAllAlertsRead } from "@/lib/api"
import type { Alert } from "@/lib/types"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { severityColor } from "@/lib/severity"
import { timeAgo } from "@/lib/format"
import { cn } from "@/lib/utils"

export default function AlertsPage() {
  const [alerts, setAlerts] = React.useState<Alert[]>([])
  const [loading, setLoading] = React.useState(true)

  const refresh = React.useCallback(() => {
    listAlerts()
      .then(setAlerts)
      .catch(() => setAlerts([]))
      .finally(() => setLoading(false))
  }, [])
  React.useEffect(() => refresh(), [refresh])

  const unread = alerts.filter((a) => !a.read).length

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <header className="flex items-end justify-between gap-4 border-b border-border pb-3">
        <div>
          <h1 className="font-display text-3xl leading-none text-phosphor-bright glow">
            // alerts {unread > 0 ? <span className="text-amber">[{unread}]</span> : null}
          </h1>
          <p className="mt-1 text-xs text-phosphor-dim">change detection — new risk on re-scan</p>
        </div>
        {unread > 0 ? (
          <Button variant="ghost" size="sm" onClick={() => markAllAlertsRead().then(refresh)}>
            mark all read
          </Button>
        ) : null}
      </header>

      {loading ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-phosphor-dim">
            <span className="blink">loading…</span>
          </CardContent>
        </Card>
      ) : alerts.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-phosphor-dim">
            no alerts. recurring scans flag new risk here.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <ul>
              {alerts.map((a) => (
                <li
                  key={a.id}
                  className={cn(
                    "flex items-center gap-3 border-b border-border/50 border-l-2 px-4 py-3 last:border-b-0",
                    a.read ? "border-l-transparent" : "border-l-amber bg-accent/40"
                  )}
                >
                  <span className={cn("h-2 w-2 shrink-0", severityColor(a.severity).dot)} />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm text-phosphor">{a.message}</p>
                    <p className="text-xs text-phosphor-dim/70">
                      <span className="text-cyan">{a.target}</span> · {timeAgo(a.created_at)}
                    </p>
                  </div>
                  {!a.read ? (
                    <button
                      onClick={() => markAlertRead(a.id).then(refresh)}
                      className="border border-border px-2 py-0.5 text-xs text-phosphor-dim transition-colors hover:border-phosphor/50 hover:text-phosphor"
                    >
                      ack
                    </button>
                  ) : (
                    <span className="text-xs text-phosphor-dim/50">read</span>
                  )}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
