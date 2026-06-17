import Link from "next/link"

import { getTargetsServer } from "@/lib/server-api"
import { Card, CardContent } from "@/components/ui/card"
import { RiskBadge } from "@/components/risk-badge"
import { timeAgo } from "@/lib/format"

export const dynamic = "force-dynamic"

export default async function TargetsPage() {
  const targets = await getTargetsServer()

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <header className="border-b border-border pb-3">
        <h1 className="font-display text-3xl leading-none text-phosphor-bright glow">// targets</h1>
        <p className="mt-1 text-xs text-phosphor-dim">monitored hosts — last observed risk</p>
      </header>

      {targets.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-phosphor-dim">
            no targets yet. <span className="text-cyan">run a scan</span> from the dashboard.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <ul>
              {targets.map((t) => (
                <li key={t.target}>
                  <Link
                    href={`/targets/${encodeURIComponent(t.target)}`}
                    className="group flex items-center justify-between gap-4 border-b border-border/50 px-4 py-3 transition-colors last:border-0 hover:bg-accent"
                  >
                    <div className="min-w-0">
                      <p className="flex items-center gap-2 truncate text-sm">
                        <span className="text-phosphor-dim group-hover:text-phosphor-bright">▸</span>
                        <span className="text-phosphor">{t.target}</span>
                      </p>
                      <p className="pl-5 text-xs text-phosphor-dim/70">
                        {t.total_scans} scan{t.total_scans === 1 ? "" : "s"} · last {timeAgo(t.last_scanned)}
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      <RiskBadge label={t.last_risk_label} score={t.last_risk_score} />
                      <span className="text-phosphor-dim transition-transform group-hover:translate-x-0.5 group-hover:text-phosphor">
                        →
                      </span>
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
