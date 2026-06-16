"use client"

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts"

import { SEVERITY_COLORS } from "@/lib/severity"

export interface DonutDatum {
  name: string
  value: number
}

export function SeverityDonut({ data, label = "total" }: { data: DonutDatum[]; label?: string }) {
  const total = data.reduce((sum, d) => sum + d.value, 0)

  if (total === 0) {
    return (
      <div className="grid h-52 place-items-center text-sm text-muted-foreground">
        No data yet
      </div>
    )
  }

  return (
    <div className="relative h-52 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data.filter((d) => d.value > 0)}
            dataKey="value"
            nameKey="name"
            innerRadius={58}
            outerRadius={86}
            paddingAngle={2}
            stroke="none"
          >
            {data
              .filter((d) => d.value > 0)
              .map((d) => (
                <Cell key={d.name} fill={SEVERITY_COLORS[d.name.toUpperCase()]?.hex ?? "#94a3b8"} />
              ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "oklch(0.21 0.025 255)",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 12,
              color: "#e2e8f0",
              fontSize: 12,
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-3xl font-bold tabular-nums">{total}</span>
        <span className="text-xs text-muted-foreground">{label}</span>
      </div>
    </div>
  )
}
