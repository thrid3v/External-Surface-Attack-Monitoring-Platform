"use client"

import * as React from "react"
import { Bell, Check, CheckCheck } from "lucide-react"

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
      <div className="flex items-end justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.3em] text-primary">Monitoring</p>
          <h1 className="font-heading text-2xl font-semibold">
            Alerts {unread > 0 ? <span className="text-orange-400">({unread})</span> : null}
          </h1>
        </div>
        {unread > 0 ? (
          <Button variant="ghost" size="sm" onClick={() => markAllAlertsRead().then(refresh)}>
            <CheckCheck className="mr-1.5 h-4 w-4" />
            Mark all read
          </Button>
        ) : null}
      </div>

      {loading ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">Loading…</CardContent>
        </Card>
      ) : alerts.length === 0 ? (
        <Card>
          <CardContent className="grid place-items-center gap-2 py-12 text-center">
            <Bell className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No alerts. Recurring scans flag new risk here.</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <ul className="divide-y divide-border">
              {alerts.map((a) => (
                <li
                  key={a.id}
                  className={cn(
                    "flex items-center gap-3 px-5 py-4",
                    !a.read && "bg-primary/[0.04]"
                  )}
                >
                  <span className={cn("h-2 w-2 shrink-0 rounded-full", severityColor(a.severity).dot)} />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm">{a.message}</p>
                    <p className="text-xs text-muted-foreground">
                      <span className="font-mono">{a.target}</span> · {timeAgo(a.created_at)}
                    </p>
                  </div>
                  {!a.read ? (
                    <button
                      onClick={() => markAlertRead(a.id).then(refresh)}
                      className="grid h-8 w-8 place-items-center rounded-lg text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                      aria-label="Mark read"
                    >
                      <Check className="h-4 w-4" />
                    </button>
                  ) : (
                    <span className="text-xs text-muted-foreground">read</span>
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
