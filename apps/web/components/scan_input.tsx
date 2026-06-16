"use client"

import * as React from "react"
import { SlidersHorizontal } from "lucide-react"

import { Button } from "./ui/button"
import { Input } from "./ui/input"
import { startScan } from "@/lib/api"
import { cn } from "@/lib/utils"

type ScanInputProps = {
  onScan: (scanId: string) => void
}

const PROFILES = [
  { id: "common", label: "Common ports" },
  { id: "top-1000", label: "Top 1000" },
  { id: "full", label: "Full (1-65535)" },
]

const MODULES = [
  { id: "port_scanner", label: "Ports" },
  { id: "cve_lookup", label: "CVEs" },
  { id: "dns_enum", label: "DNS" },
  { id: "osint_fetcher", label: "OSINT" },
  { id: "service_probe", label: "HTTP/TLS" },
]

function normalizeTarget(rawTarget: string) {
  let target = rawTarget.trim()
  if (!target) return ""
  const lower = target.toLowerCase()
  if (lower.startsWith("http://")) target = target.slice(7)
  else if (lower.startsWith("https://")) target = target.slice(8)
  const slash = target.indexOf("/")
  if (slash !== -1) target = target.slice(0, slash)
  return target.trim()
}

export default function ScanInput({ onScan }: ScanInputProps) {
  const [value, setValue] = React.useState("")
  const [loading, setLoading] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [profile, setProfile] = React.useState("top-1000")
  const [showAdvanced, setShowAdvanced] = React.useState(false)
  const [modules, setModules] = React.useState<string[]>(MODULES.map((m) => m.id))

  const toggleModule = (id: string) =>
    setModules((prev) => (prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]))

  const handleSubmit = React.useCallback(async () => {
    setLoading(true)
    setError(null)

    const trimmed = value.trim()
    if (!trimmed || /\s/.test(trimmed)) {
      setError("Enter a valid URL, domain, or IP address.")
      setLoading(false)
      return
    }
    const target = normalizeTarget(trimmed)
    if (!target) {
      setError("Enter a valid URL, domain, or IP address.")
      setLoading(false)
      return
    }

    try {
      const result = await startScan(target, {
        profile,
        modules: modules.length && modules.length < MODULES.length ? modules : undefined,
      })
      onScan(result.scan_id)
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred.")
    } finally {
      setLoading(false)
    }
  }, [onScan, value, profile, modules])

  return (
    <div className="flex w-full flex-col gap-3">
      <div className="flex w-full items-center gap-2">
        <Input
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault()
              void handleSubmit()
            }
          }}
          disabled={loading}
          aria-invalid={!!error}
          placeholder="example.com · 192.168.1.1"
          className="min-w-0 font-mono"
        />
        <Button onClick={handleSubmit} disabled={loading} type="button">
          {loading ? (
            <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
          ) : (
            "Scan"
          )}
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {PROFILES.map((p) => (
          <button
            key={p.id}
            type="button"
            onClick={() => setProfile(p.id)}
            className={cn(
              "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
              profile === p.id
                ? "border-primary/40 bg-primary/15 text-primary"
                : "border-border text-muted-foreground hover:text-foreground"
            )}
          >
            {p.label}
          </button>
        ))}
        <button
          type="button"
          onClick={() => setShowAdvanced((s) => !s)}
          className={cn(
            "ml-auto inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors",
            showAdvanced ? "border-primary/40 text-primary" : "border-border text-muted-foreground hover:text-foreground"
          )}
        >
          <SlidersHorizontal className="h-3.5 w-3.5" />
          Modules
        </button>
      </div>

      {showAdvanced ? (
        <div className="flex flex-wrap gap-2 rounded-xl border border-border bg-muted/30 p-3">
          {MODULES.map((m) => {
            const on = modules.includes(m.id)
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => toggleModule(m.id)}
                className={cn(
                  "rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors",
                  on ? "border-primary/40 bg-primary/15 text-primary" : "border-border text-muted-foreground"
                )}
              >
                {m.label}
              </button>
            )
          })}
        </div>
      ) : null}

      {error ? <p className="text-sm text-destructive">{error}</p> : null}
    </div>
  )
}
