export type SeverityKey = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL" | "NONE"

export interface SeverityStyle {
  text: string
  bg: string
  border: string
  dot: string
  hex: string
}

// ANSI-terminal severity palette: red / amber / yellow / blue / phosphor.
export const SEVERITY_COLORS: Record<string, SeverityStyle> = {
  CRITICAL: { text: "text-red", bg: "bg-red/10", border: "border-red/40", dot: "bg-red", hex: "#ff4d5e" },
  HIGH: { text: "text-amber", bg: "bg-amber/10", border: "border-amber/40", dot: "bg-amber", hex: "#ffb000" },
  MEDIUM: { text: "text-yellow", bg: "bg-yellow/10", border: "border-yellow/40", dot: "bg-yellow", hex: "#e8d44a" },
  LOW: { text: "text-cyan", bg: "bg-cyan/10", border: "border-cyan/40", dot: "bg-cyan", hex: "#4d9fff" },
  MINIMAL: { text: "text-phosphor", bg: "bg-phosphor/10", border: "border-phosphor/40", dot: "bg-phosphor", hex: "#43d675" },
  NONE: { text: "text-phosphor-dim", bg: "bg-phosphor/5", border: "border-border", dot: "bg-phosphor-dim", hex: "#2f9e54" },
  // an incomplete scan: not "clean", just unknown — muted, never green
  UNKNOWN: { text: "text-phosphor-dim", bg: "bg-muted", border: "border-border", dot: "bg-phosphor-dim", hex: "#5a6b5a" },
}

export function severityColor(label?: string | null): SeverityStyle {
  return SEVERITY_COLORS[(label ?? "UNKNOWN").toUpperCase()] ?? SEVERITY_COLORS.UNKNOWN
}

/** Risk labels share the severity palette (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL). */
export const riskColor = severityColor
