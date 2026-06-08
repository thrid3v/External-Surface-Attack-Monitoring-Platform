"use client"

import { useEffect, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"

const SEVERITY_COLORS: Record<string, { text: string; bg: string; border: string }> = {
  CRITICAL: { text: "text-red-500",    bg: "bg-red-50 dark:bg-red-950",      border: "border-l-red-500" },
  HIGH:     { text: "text-orange-500", bg: "bg-orange-50 dark:bg-orange-950", border: "border-l-orange-500" },
  MEDIUM:   { text: "text-yellow-500", bg: "bg-yellow-50 dark:bg-yellow-950", border: "border-l-yellow-500" },
  LOW:      { text: "text-blue-500",   bg: "bg-blue-50 dark:bg-blue-950",     border: "border-l-blue-500" },
  MINIMAL:  { text: "text-gray-500",   bg: "bg-gray-50 dark:bg-gray-900",     border: "border-l-gray-400" },
}

const STAT_ROWS = [
  { key: "critical", label: "CRITICAL", colorKey: "CRITICAL" },
  { key: "high",     label: "HIGH",     colorKey: "HIGH" },
  { key: "medium",   label: "MEDIUM",   colorKey: "MEDIUM" },
  { key: "low",      label: "LOW",      colorKey: "LOW" },
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
    if (score === 0) return
    let current = 0
    const step = Math.max(1, Math.ceil(score / 40))
    const timer = setInterval(() => {
      current = Math.min(current + step, score)
      setDisplayScore(current)
      if (current >= score) clearInterval(timer)
    }, 20)
    return () => clearInterval(timer)
  }, [score])

  const colors = SEVERITY_COLORS[label] ?? SEVERITY_COLORS.MINIMAL

  return (
    <Card className={`rounded-3xl border-l-4 ${colors.border}`}>
      <CardContent className="pt-6">
        <div className="grid gap-6 sm:grid-cols-[auto_1fr]">
          <div className="space-y-2">
            <p className={`text-8xl font-bold tabular-nums leading-none ${colors.text}`}>
              {displayScore}
            </p>
            <Badge className={`${colors.text} ${colors.bg} border-0 text-xs font-semibold`}>
              {label}
            </Badge>
            <p className="font-mono text-sm text-muted-foreground">{target}</p>
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {STAT_ROWS.map(({ key, label: sLabel, colorKey }) => {
              const c = SEVERITY_COLORS[colorKey]
              return (
                <div key={key} className={`rounded-2xl p-4 ${c.bg} space-y-1 text-center`}>
                  <p className={`text-2xl font-bold ${c.text}`}>{severitySummary[key] ?? 0}</p>
                  <p className="text-xs text-muted-foreground">{sLabel}</p>
                </div>
              )
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
