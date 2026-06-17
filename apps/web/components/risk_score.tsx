"use client"

import { useEffect, useState } from "react"
import { Card, CardContent } from "@/components/ui/card"
import { RiskBadge } from "@/components/risk-badge"
import { severityColor } from "@/lib/severity"
import { cn } from "@/lib/utils"

const STAT_ROWS = [
  { key: "critical", label: "crit", sev: "CRITICAL" },
  { key: "high", label: "high", sev: "HIGH" },
  { key: "medium", label: "med", sev: "MEDIUM" },
  { key: "low", label: "low", sev: "LOW" },
]

interface RiskScoreProps {
  score: number
  label: string
  severitySummary: Record<string, number>
  target: string
}

export default function RiskScore({ score, label, severitySummary, target }: RiskScoreProps) {
  const [displayScore, setDisplayScore] = useState(0)

  useEffect(() => {
    if (score === 0) {
      setDisplayScore(0)
      return
    }
    let current = 0
    const step = Math.max(1, Math.ceil(score / 40))
    const timer = setInterval(() => {
      current = Math.min(current + step, score)
      setDisplayScore(current)
      if (current >= score) clearInterval(timer)
    }, 20)
    return () => clearInterval(timer)
  }, [score])

  const c = severityColor(label)

  return (
    <Card className={cn("border-l-2", c.border)}>
      <CardContent className="grid gap-6 pt-2 sm:grid-cols-[auto_1fr]">
        <div>
          <p className="text-xs text-phosphor-dim">// risk_score</p>
          <p className={cn("font-display text-7xl leading-none tabular-nums glow-strong", c.text)}>
            {String(displayScore).padStart(2, "0")}
            <span className="text-2xl text-phosphor-dim">/100</span>
          </p>
          <div className="mt-2 flex items-center gap-2">
            <RiskBadge label={label} />
            <span className="text-sm text-cyan">{target}</span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 self-center sm:grid-cols-4">
          {STAT_ROWS.map(({ key, label: sLabel, sev }) => {
            const cc = severityColor(sev)
            return (
              <div key={key} className={cn("border p-3 text-center", cc.border)}>
                <p className={cn("font-display text-3xl leading-none tabular-nums", cc.text)}>
                  {severitySummary[key] ?? 0}
                </p>
                <p className="mt-1 text-[10px] uppercase tracking-[0.2em] text-phosphor-dim">{sLabel}</p>
              </div>
            )
          })}
        </div>
      </CardContent>
    </Card>
  )
}
