"use client"

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts"

export interface TrendDatum {
  label: string
  risk: number
}

export function RiskTrend({ data }: { data: TrendDatum[] }) {
  if (data.length === 0) {
    return (
      <div className="grid h-56 place-items-center text-sm text-phosphor-dim">
        no history yet
      </div>
    )
  }

  return (
    <div className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
          <defs>
            <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#43d675" stopOpacity={0.35} />
              <stop offset="100%" stopColor="#43d675" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#16361f" vertical={false} />
          <XAxis dataKey="label" tick={{ fill: "#2f9e54", fontSize: 11 }} axisLine={false} tickLine={false} />
          <YAxis domain={[0, 100]} tick={{ fill: "#2f9e54", fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{
              background: "#0c0c0c",
              border: "1px solid #16361f",
              borderRadius: 0,
              color: "#43d675",
              fontSize: 12,
              fontFamily: "var(--font-jetbrains), monospace",
            }}
            cursor={{ stroke: "#2f9e54", strokeDasharray: "3 3" }}
          />
          <Area type="monotone" dataKey="risk" stroke="#43d675" strokeWidth={2} fill="url(#riskFill)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
