export type SeverityKey = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL" | "NONE"

export interface SeverityStyle {
  text: string
  bg: string
  border: string
  dot: string
  hex: string
}

export const SEVERITY_COLORS: Record<string, SeverityStyle> = {
  CRITICAL: { text: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", dot: "bg-red-500", hex: "#ef4444" },
  HIGH: { text: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", dot: "bg-orange-500", hex: "#f97316" },
  MEDIUM: { text: "text-amber-300", bg: "bg-amber-500/10", border: "border-amber-500/30", dot: "bg-amber-400", hex: "#f59e0b" },
  LOW: { text: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/30", dot: "bg-sky-500", hex: "#38bdf8" },
  MINIMAL: { text: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/30", dot: "bg-slate-500", hex: "#94a3b8" },
  NONE: { text: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/30", dot: "bg-slate-500", hex: "#94a3b8" },
}

export function severityColor(label?: string | null): SeverityStyle {
  return SEVERITY_COLORS[(label ?? "MINIMAL").toUpperCase()] ?? SEVERITY_COLORS.MINIMAL
}

/** Risk labels share the severity palette (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL). */
export const riskColor = severityColor
