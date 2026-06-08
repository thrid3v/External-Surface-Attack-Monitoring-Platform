"use client"

import { CheckCircle, Loader2, Minus } from "lucide-react"
import { Card, CardContent } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"

const MODULES = [
  { key: "port_scanner",  label: "Port scan" },
  { key: "cve_lookup",    label: "CVE lookup" },
  { key: "dns_enum",      label: "DNS enumeration" },
  { key: "osint_fetcher", label: "OSINT fetch" },
  { key: "service_probe", label: "Service probe" },
  { key: "report_gen",    label: "Generating report" },
]

interface ScanProgressProps {
  currentModule: string | null
  target: string
}

export default function ScanProgress({ currentModule, target }: ScanProgressProps) {
  const currentIndex = currentModule ? MODULES.findIndex((m) => m.key === currentModule) : -1
  const percentage = currentIndex >= 0 ? ((currentIndex + 1) / MODULES.length) * 100 : 0

  return (
    <Card className="rounded-3xl border border-border">
      <CardContent className="space-y-6 pt-6">
        <div>
          <h2 className="text-xl font-semibold">Scanning {target}…</h2>
          <p className="mt-1 text-sm text-muted-foreground">This usually takes 1–3 minutes. Port scanning may appear paused while nmap runs.</p>
        </div>

        <Progress value={percentage} className="h-2" />

        <ul className="space-y-3">
          {MODULES.map((mod, index) => {
            let state: "complete" | "running" | "pending" = "pending"
            if (index < currentIndex) state = "complete"
            else if (mod.key === currentModule) state = "running"

            return (
              <li key={mod.key} className="flex items-center gap-3 text-sm">
                {state === "complete" && (
                  <CheckCircle className="h-4 w-4 shrink-0 text-green-500" />
                )}
                {state === "running" && (
                  <Loader2 className="h-4 w-4 shrink-0 animate-spin text-primary" />
                )}
                {state === "pending" && (
                  <Minus className="h-4 w-4 shrink-0 text-muted-foreground" />
                )}
                <span className={state === "pending" ? "text-muted-foreground" : "text-foreground"}>
                  {mod.label}
                </span>
              </li>
            )
          })}
        </ul>
      </CardContent>
    </Card>
  )
}
