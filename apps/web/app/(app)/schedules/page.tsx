"use client"

import * as React from "react"
import { CalendarClock, Trash2, Plus } from "lucide-react"

import {
  listSchedules,
  createSchedule,
  toggleSchedule,
  deleteSchedule,
} from "@/lib/api"
import type { Schedule } from "@/lib/types"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { timeAgo } from "@/lib/format"
import { cn } from "@/lib/utils"

const PROFILES = [
  { id: "common", label: "Common" },
  { id: "top-1000", label: "Top 1000" },
  { id: "full", label: "Full" },
]
const INTERVALS = [
  { v: 60, label: "Hourly" },
  { v: 1440, label: "Daily" },
  { v: 10080, label: "Weekly" },
]

export default function SchedulesPage() {
  const [schedules, setSchedules] = React.useState<Schedule[]>([])
  const [target, setTarget] = React.useState("")
  const [profile, setProfile] = React.useState("top-1000")
  const [interval, setInterval] = React.useState(1440)
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)

  const refresh = React.useCallback(() => {
    listSchedules().then(setSchedules).catch(() => setSchedules([]))
  }, [])
  React.useEffect(() => refresh(), [refresh])

  const onCreate = async () => {
    const t = target.trim().toLowerCase()
    if (!t) {
      setError("Enter a target")
      return
    }
    setBusy(true)
    setError(null)
    try {
      await createSchedule({ target: t, profile, interval_minutes: interval })
      setTarget("")
      refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create schedule")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <p className="text-xs font-medium uppercase tracking-[0.3em] text-primary">Automation</p>
        <h1 className="font-heading text-2xl font-semibold">Recurring scans</h1>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm uppercase tracking-wider text-muted-foreground">New schedule</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-col gap-2 sm:flex-row">
            <Input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com"
              className="font-mono"
            />
            <Button onClick={onCreate} disabled={busy} className="shrink-0">
              <Plus className="mr-1.5 h-4 w-4" />
              Add
            </Button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {PROFILES.map((p) => (
              <button
                key={p.id}
                onClick={() => setProfile(p.id)}
                className={cn(
                  "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
                  profile === p.id ? "border-primary/40 bg-primary/15 text-primary" : "border-border text-muted-foreground"
                )}
              >
                {p.label}
              </button>
            ))}
            <span className="mx-1 text-border">|</span>
            {INTERVALS.map((i) => (
              <button
                key={i.v}
                onClick={() => setInterval(i.v)}
                className={cn(
                  "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
                  interval === i.v ? "border-primary/40 bg-primary/15 text-primary" : "border-border text-muted-foreground"
                )}
              >
                {i.label}
              </button>
            ))}
          </div>
          {error ? <p className="text-sm text-destructive">{error}</p> : null}
        </CardContent>
      </Card>

      {schedules.length === 0 ? (
        <Card>
          <CardContent className="grid place-items-center gap-2 py-12 text-center">
            <CalendarClock className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No schedules yet.</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <ul className="divide-y divide-border">
              {schedules.map((s) => (
                <li key={s.id} className="flex items-center justify-between gap-3 px-5 py-4">
                  <div className="min-w-0">
                    <p className="truncate font-mono text-sm font-medium">{s.target}</p>
                    <p className="text-xs text-muted-foreground">
                      {s.profile ?? s.port_range} · every {s.interval_minutes >= 1440 ? `${s.interval_minutes / 1440}d` : `${s.interval_minutes / 60}h`} · next{" "}
                      {timeAgo(s.next_run_at)}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => toggleSchedule(s.id).then(refresh)}
                      className={cn(
                        "rounded-full border px-3 py-1 text-xs font-medium",
                        s.enabled ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400" : "border-border text-muted-foreground"
                      )}
                    >
                      {s.enabled ? "Enabled" : "Paused"}
                    </button>
                    <button
                      onClick={() => deleteSchedule(s.id).then(refresh)}
                      className="grid h-8 w-8 place-items-center rounded-lg text-muted-foreground transition-colors hover:bg-destructive/10 hover:text-destructive"
                      aria-label="Delete schedule"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
