"use client"

import { Card, CardContent } from "@/components/ui/card"
import { Progress } from "@/components/ui/progress"
import { cn } from "@/lib/utils"

// Mirrors MODULE_ORDER in the backend (apps/api/constants.py).
const MODULES = [
  { key: "port_scanner", label: "port scan" },
  { key: "cve_lookup", label: "cve lookup" },
  { key: "dns_enum", label: "dns enumeration" },
  { key: "osint_fetcher", label: "osint fetch" },
  { key: "service_probe", label: "service / tls probe" },
  { key: "web_audit", label: "web exposure audit" },
  { key: "takeover_check", label: "subdomain takeover" },
  { key: "email_audit", label: "email posture" },
  { key: "nuclei_scan", label: "nuclei templates" },
]

interface ScanProgressProps {
  currentModule: string | null
  target: string
}

export default function ScanProgress({ currentModule, target }: ScanProgressProps) {
  const currentIndex = currentModule ? MODULES.findIndex((m) => m.key === currentModule) : -1
  const completed = currentIndex >= 0 ? currentIndex : 0
  const percentage = Math.round((completed / MODULES.length) * 100)

  return (
    <Card>
      <CardContent className="space-y-4 pt-2">
        <div className="flex items-baseline gap-2">
          <span className="text-phosphor-dim">$</span>
          <span className="text-phosphor">easm scan</span>
          <span className="text-cyan">{target}</span>
          <span className="blink text-phosphor-bright">▋</span>
        </div>
        <p className="text-xs text-phosphor-dim">
          running — typically 1–3 min. nmap may appear paused during the port sweep.
        </p>

        <div className="flex items-center gap-3">
          <Progress value={percentage} className="h-2 flex-1" />
          <span className="font-display text-lg tabular-nums text-phosphor">{percentage}%</span>
        </div>

        <ul className="space-y-1 text-sm">
          {MODULES.map((mod, index) => {
            let state: "complete" | "running" | "pending" = "pending"
            if (index < currentIndex) state = "complete"
            else if (mod.key === currentModule) state = "running"

            const marker =
              state === "complete" ? "[ ok ]" : state === "running" ? "[>>>>]" : "[    ]"

            return (
              <li key={mod.key} className="flex items-center gap-3">
                <span
                  className={cn(
                    "font-mono",
                    state === "complete" && "text-phosphor",
                    state === "running" && "text-phosphor-bright glow blink",
                    state === "pending" && "text-phosphor-dim/40"
                  )}
                >
                  {marker}
                </span>
                <span
                  className={cn(
                    state === "complete" && "text-phosphor-dim",
                    state === "running" && "text-phosphor",
                    state === "pending" && "text-phosphor-dim/40"
                  )}
                >
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
