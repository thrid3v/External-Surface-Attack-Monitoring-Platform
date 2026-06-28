import { cn } from "@/lib/utils"
import { severityColor } from "@/lib/severity"

/** Risk/severity rendered as a terminal bracket tag, e.g. [CRITICAL:88]. */
export function RiskBadge({
  label,
  score,
  className,
}: {
  label?: string | null
  score?: number | null
  className?: string
}) {
  const c = severityColor(label)
  return (
    <span
      className={cn(
        "inline-flex items-center border px-1.5 font-mono text-[11px] uppercase tracking-wider",
        c.text,
        c.border,
        className
      )}
    >
      {label ?? "UNKNOWN"}
      {typeof score === "number" ? <span className="opacity-70">:{score}</span> : null}
    </span>
  )
}
