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
      <div className="grid h-52 place-items-center text-sm text-phosphor-dim">
        no data yet
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
                <Cell key={d.name} fill={SEVERITY_COLORS[d.name.toUpperCase()]?.hex ?? "#2f9e54"} />
              ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "#0d130d",
              border: "1px solid #16361f",
              borderRadius: 0,
              color: "#43d675",
              fontSize: 12,
              fontFamily: "var(--font-jetbrains), monospace",
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-display text-4xl leading-none tabular-nums text-phosphor glow">{total}</span>
        <span className="text-xs text-phosphor-dim">{label}</span>
      </div>
    </div>
  )
}
