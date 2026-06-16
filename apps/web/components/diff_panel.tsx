import { TrendingDown, TrendingUp, Minus } from "lucide-react"

import type { DiffResult } from "@/lib/types"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { severityColor } from "@/lib/severity"
import { cn } from "@/lib/utils"

export function DiffPanel({ diff }: { diff: DiffResult }) {
  if (!diff.compared_to) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Changes since last scan</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          First scan of this target — nothing to compare yet.
        </CardContent>
      </Card>
    )
  }

  const delta = diff.risk_delta ?? 0
  const DeltaIcon = delta > 0 ? TrendingUp : delta < 0 ? TrendingDown : Minus
  const deltaColor = delta > 0 ? "text-red-400" : delta < 0 ? "text-emerald-400" : "text-muted-foreground"

  const noChange =
    !diff.new_cves.length &&
    !diff.resolved_cves.length &&
    !diff.opened_ports.length &&
    !diff.closed_ports.length &&
    delta === 0

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>Changes since last scan</CardTitle>
        <span className={cn("inline-flex items-center gap-1.5 text-sm font-semibold", deltaColor)}>
          <DeltaIcon className="h-4 w-4" />
          {delta > 0 ? `+${delta}` : delta} risk
          <span className="text-xs font-normal text-muted-foreground">
            ({diff.previous_risk ?? "—"} → {diff.current_risk ?? "—"})
          </span>
        </span>
      </CardHeader>
      <CardContent>
        {noChange ? (
          <p className="text-sm text-muted-foreground">No changes detected versus the previous scan.</p>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2">
            <DiffList title="New vulnerabilities" tone="bad" items={diff.new_cves.map((c) => ({ key: c.cve_id, label: c.cve_id, sev: c.severity }))} />
            <DiffList title="Resolved" tone="good" items={diff.resolved_cves.map((c) => ({ key: c.cve_id, label: c.cve_id, sev: c.severity }))} />
            <DiffList title="Opened ports" tone="bad" items={diff.opened_ports.map((p) => ({ key: String(p), label: String(p) }))} />
            <DiffList title="Closed ports" tone="good" items={diff.closed_ports.map((p) => ({ key: String(p), label: String(p) }))} />
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function DiffList({
  title,
  tone,
  items,
}: {
  title: string
  tone: "good" | "bad"
  items: { key: string; label: string; sev?: string }[]
}) {
  const toneColor = tone === "bad" ? "text-red-400" : "text-emerald-400"
  return (
    <div>
      <p className={cn("mb-2 text-xs font-semibold uppercase tracking-wider", toneColor)}>
        {title} <span className="text-muted-foreground">({items.length})</span>
      </p>
      {items.length === 0 ? (
        <p className="text-xs text-muted-foreground">None</p>
      ) : (
        <ul className="flex flex-wrap gap-1.5">
          {items.map((it) => (
            <li
              key={it.key}
              className={cn(
                "rounded-md border px-2 py-0.5 font-mono text-xs",
                it.sev ? severityColor(it.sev).border : "border-border",
                it.sev ? severityColor(it.sev).text : "text-foreground"
              )}
            >
              {it.label}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
