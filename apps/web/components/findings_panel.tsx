import { ShieldCheck } from "lucide-react"

import type { Finding } from "@/lib/types"
import { Card, CardContent } from "@/components/ui/card"
import { severityColor } from "@/lib/severity"
import { cn } from "@/lib/utils"

const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

export function FindingsPanel({ findings }: { findings: Finding[] }) {
  if (!findings || findings.length === 0) {
    return (
      <Card>
        <CardContent className="grid place-items-center gap-2 py-12 text-center">
          <span className="grid h-12 w-12 place-items-center border border-phosphor/40 bg-phosphor/5">
            <ShieldCheck className="h-6 w-6 text-phosphor" />
          </span>
          <p className="font-display text-xl text-phosphor-bright glow">no exposures detected</p>
          <p className="text-sm text-phosphor-dim">
            web, tls, takeover, email, and template checks found nothing.
          </p>
        </CardContent>
      </Card>
    )
  }

  const sorted = [...findings].sort(
    (a, b) =>
      (ORDER.indexOf(a.severity.toUpperCase()) + 1 || 99) -
      (ORDER.indexOf(b.severity.toUpperCase()) + 1 || 99)
  )

  return (
    <div className="space-y-3">
      {sorted.map((f, i) => {
        const c = severityColor(f.severity)
        return (
          <Card key={`${f.title}-${i}`} className={cn("border-l-4", c.border)}>
            <CardContent className="space-y-2 pt-6">
              <div className="flex flex-wrap items-center gap-2">
                <span className={cn("border px-1.5 text-[11px] uppercase tracking-wider", c.border, c.text)}>
                  {f.severity.toUpperCase()}
                </span>
                <span className="border border-border px-1.5 text-[11px] uppercase tracking-wider text-phosphor-dim">
                  {f.category}
                </span>
                <span className="text-phosphor">{f.title}</span>
              </div>
              {f.target ? <p className="font-mono text-xs text-muted-foreground">{f.target}</p> : null}
              {f.description ? <p className="text-sm text-muted-foreground">{f.description}</p> : null}
              {f.evidence ? (
                <pre className="overflow-x-auto border border-border bg-bg-inset px-3 py-2 text-xs text-phosphor-dim">
                  {f.evidence}
                </pre>
              ) : null}
              {f.remediation ? (
                <p className="text-xs">
                  <span className="text-amber">fix: </span>
                  <span className="text-phosphor-dim">{f.remediation}</span>
                </p>
              ) : null}
              {f.references && f.references.length > 0 ? (
                <div className="flex flex-wrap gap-2 pt-1">
                  {f.references.slice(0, 3).map((r) => (
                    <a
                      key={r}
                      href={r}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-cyan hover:underline"
                    >
                      ref ↗
                    </a>
                  ))}
                </div>
              ) : null}
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}
