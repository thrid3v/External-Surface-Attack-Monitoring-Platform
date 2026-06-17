"use client"

import * as React from "react"

import { Button } from "./ui/button"
import { Input } from "./ui/input"
import { startScan } from "@/lib/api"
import { cn } from "@/lib/utils"

type ScanInputProps = {
  onScan: (scanId: string) => void
}

const PROFILES = [
  { id: "common", label: "common" },
  { id: "top-1000", label: "top-1000" },
  { id: "full", label: "full" },
]

const MODULES = [
  { id: "port_scanner", label: "ports" },
  { id: "cve_lookup", label: "cves" },
  { id: "dns_enum", label: "dns" },
  { id: "osint_fetcher", label: "osint" },
  { id: "service_probe", label: "http/tls" },
  { id: "web_audit", label: "web" },
  { id: "takeover_check", label: "takeover" },
  { id: "email_audit", label: "email" },
  { id: "nuclei_scan", label: "nuclei" },
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

function Tag({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "border px-2 py-0.5 text-xs lowercase transition-colors",
        active
          ? "border-phosphor/60 bg-accent text-phosphor-bright"
          : "border-border text-phosphor-dim hover:text-phosphor"
      )}
    >
      {active ? "[x] " : "[ ] "}
      {children}
    </button>
  )
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
      setError("enter a valid url, domain, or ip address")
      setLoading(false)
      return
    }
    const target = normalizeTarget(trimmed)
    if (!target) {
      setError("enter a valid url, domain, or ip address")
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
      setError(err instanceof Error ? err.message : "an unexpected error occurred")
    } finally {
      setLoading(false)
    }
  }, [onScan, value, profile, modules])

  return (
    <div className="flex w-full flex-col gap-3">
      <div className="flex w-full items-center gap-2">
        <span className="font-mono text-phosphor-bright">❯</span>
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
          placeholder="scan example.com  ·  192.168.1.1"
          className="min-w-0 flex-1"
        />
        <Button onClick={handleSubmit} disabled={loading} type="button">
          {loading ? <span className="blink">scanning…</span> : "run ❯"}
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-phosphor-dim">--ports</span>
        {PROFILES.map((p) => (
          <button
            key={p.id}
            type="button"
            onClick={() => setProfile(p.id)}
            className={cn(
              "border px-2 py-0.5 lowercase transition-colors",
              profile === p.id
                ? "border-phosphor/60 bg-accent text-phosphor-bright"
                : "border-border text-phosphor-dim hover:text-phosphor"
            )}
          >
            {p.label}
          </button>
        ))}
        <button
          type="button"
          onClick={() => setShowAdvanced((s) => !s)}
          className={cn(
            "ml-auto border px-2 py-0.5 transition-colors",
            showAdvanced ? "border-phosphor/60 text-phosphor" : "border-border text-phosphor-dim hover:text-phosphor"
          )}
        >
          {showAdvanced ? "[-] modules" : "[+] modules"}
        </button>
      </div>

      {showAdvanced ? (
        <div className="flex flex-wrap gap-2 border border-border bg-bg-inset p-3">
          {MODULES.map((m) => (
            <Tag key={m.id} active={modules.includes(m.id)} onClick={() => toggleModule(m.id)}>
              {m.label}
            </Tag>
          ))}
        </div>
      ) : null}

      {error ? <p className="text-sm text-red">! {error}</p> : null}
    </div>
  )
}
