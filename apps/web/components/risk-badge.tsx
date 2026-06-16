import { cn } from "@/lib/utils"
import { severityColor } from "@/lib/severity"

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
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        c.bg,
        c.border,
        c.text,
        className
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", c.dot)} />
      {label ?? "UNKNOWN"}
      {typeof score === "number" ? <span className="opacity-70">· {score}</span> : null}
    </span>
  )
}
