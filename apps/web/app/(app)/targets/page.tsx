import Link from "next/link"
import { Crosshair, ChevronRight } from "lucide-react"

import { getTargetsServer } from "@/lib/server-api"
import { Card, CardContent } from "@/components/ui/card"
import { RiskBadge } from "@/components/risk-badge"
import { timeAgo } from "@/lib/format"

export const dynamic = "force-dynamic"

export default async function TargetsPage() {
  const targets = await getTargetsServer()

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <p className="text-xs font-medium uppercase tracking-[0.3em] text-primary">Inventory</p>
        <h1 className="font-heading text-2xl font-semibold">Targets</h1>
      </div>

      {targets.length === 0 ? (
        <Card>
          <CardContent className="grid place-items-center gap-2 py-12 text-center">
            <Crosshair className="h-8 w-8 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">No targets yet. Run a scan from the dashboard.</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <ul className="divide-y divide-border">
              {targets.map((t) => (
                <li key={t.target}>
                  <Link
                    href={`/targets/${encodeURIComponent(t.target)}`}
                    className="group flex items-center justify-between gap-4 px-5 py-4 transition-colors hover:bg-muted/30"
                  >
                    <div className="min-w-0">
                      <p className="truncate font-mono text-sm font-medium">{t.target}</p>
                      <p className="text-xs text-muted-foreground">
                        {t.total_scans} scan{t.total_scans === 1 ? "" : "s"} · last {timeAgo(t.last_scanned)}
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      <RiskBadge label={t.last_risk_label} score={t.last_risk_score} />
                      <ChevronRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
