"use client"

import * as React from "react"
import { Check, ExternalLink, ChevronDown, ChevronUp, X } from "lucide-react"

import { Badge } from "./ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card"
import { cn } from "@/lib/utils"
import type { CertInfo, HttpFinding } from "@/lib/types"

const ALL_HEADERS = [
  "Content-Security-Policy",
  "X-Frame-Options",
  "Strict-Transport-Security",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "Permissions-Policy",
] as const

function statusBadgeProps(statusCode: number) {
  if (statusCode === 200) return { className: "border-phosphor/50 text-phosphor" }
  if (statusCode === 301 || statusCode === 302) return { className: "border-cyan/50 text-cyan" }
  if (statusCode === 403) return { className: "border-amber/50 text-amber" }
  if (statusCode === 500) return { variant: "destructive" as const }
  return { className: "border-border text-phosphor-dim" }
}

function formatDate(value?: string | null) {
  if (!value) return "Unknown"

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return "Unknown"
  }

  return date.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  })
}

function certStatusBanner(cert: CertInfo | null) {
  if (!cert) return null

  if (cert.is_expired) {
    return { text: "cert EXPIRED", className: "border-red/50 text-red" }
  }

  if (cert.days_until_expiry !== null && cert.days_until_expiry !== undefined && cert.days_until_expiry < 30) {
    return { text: `expires in ${cert.days_until_expiry}d`, className: "border-amber/50 text-amber" }
  }

  return { text: "valid", className: "border-phosphor/50 text-phosphor" }
}

function isTlsOutdated(version?: string | null) {
  return !!version && /1\.0|1\.1/.test(version)
}

function HttpPanel({ httpFindings }: { httpFindings: HttpFinding[] }) {
  const [showAll, setShowAll] = React.useState(false)
  const [showSans, setShowSans] = React.useState<Record<string, boolean>>({})

  const visibleFindings = React.useMemo(() => {
    if (httpFindings.length > 5 && !showAll) {
      return httpFindings.slice(0, 3)
    }

    return httpFindings
  }, [httpFindings, showAll])

  if (!httpFindings.length) {
    return (
      <div className="rounded-3xl border border-border bg-card px-6 py-16 text-center text-sm text-muted-foreground">
        No HTTP services found — no web services detected on this target.
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {visibleFindings.map((finding) => {
        const presentHeaders = ALL_HEADERS.filter(
          (header) => !finding.missing_headers.includes(header)
        ).length
        const serverInfoProvided =
          !!finding.server_header || !!finding.powered_by || !!finding.cms_detected
        const cert = finding.cert ?? null
        const certBanner = certStatusBanner(cert)
        const tlsOutdated = isTlsOutdated(cert?.tls_version)
        const sanOpen = showSans[finding.url] ?? false

        return (
          <Card key={finding.url} className="space-y-4 rounded-3xl border border-border bg-background">
            <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex min-w-0 items-center gap-2">
                <a
                  href={finding.url}
                  target="_blank"
                  rel="noreferrer"
                  className="font-medium text-foreground transition-colors hover:text-primary"
                >
                  {finding.url}
                </a>
                <ExternalLink className="h-4 w-4 text-muted-foreground" />
              </div>
              <Badge className="text-sm" {...statusBadgeProps(finding.status_code ?? 0)}>
                {finding.status_code}
              </Badge>
            </CardHeader>

            <CardContent>
              <div
                className={cn(
                  "grid gap-6",
                  cert ? "lg:grid-cols-[1.1fr_1fr_1fr]" : "lg:grid-cols-[1.2fr_1fr]"
                )}
              >
                <section className="space-y-4 rounded-3xl border border-border bg-card p-4">
                  <div className="flex items-center justify-between gap-3">
                    <CardTitle className="text-sm">Server Info</CardTitle>
                    {finding.cms_detected ? (
                      <Badge className="border-amber/50 text-amber">
                        cms detected
                      </Badge>
                    ) : null}
                  </div>
                  {serverInfoProvided ? (
                    <div className="space-y-3 text-sm text-muted-foreground">
                      {finding.server_header ? (
                        <div>
                          <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                            Server header
                          </div>
                          <div className="mt-1 text-sm text-foreground">{finding.server_header}</div>
                        </div>
                      ) : null}
                      {finding.powered_by ? (
                        <div>
                          <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                            X-Powered-By
                          </div>
                          <div className="mt-1 text-sm text-foreground">{finding.powered_by}</div>
                        </div>
                      ) : null}
                      {finding.cms_detected ? (
                        <div className="border border-amber/40 bg-amber/5 px-3 py-2 text-sm text-amber">
                          {finding.cms_detected}
                        </div>
                      ) : null}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">No server info disclosed</p>
                  )}
                </section>

                <section className="space-y-4 rounded-3xl border border-border bg-card p-4">
                  <CardTitle className="text-sm">Security Headers</CardTitle>
                  <div className="space-y-2 text-sm">
                    {ALL_HEADERS.map((header) => {
                      const present = !finding.missing_headers.includes(header)
                      return (
                        <div key={header} className="flex items-center justify-between gap-3 rounded-2xl border border-border bg-background px-3 py-2">
                          <span>{header}</span>
                          <span className="inline-flex items-center gap-1 px-2 py-1 text-xs">
                            {present ? (
                              <Check className="h-3.5 w-3.5 text-phosphor" />
                            ) : (
                              <X className="h-3.5 w-3.5 text-red" />
                            )}
                            <span className={present ? "text-phosphor" : "text-red"}>
                              {present ? "present" : "missing"}
                            </span>
                          </span>
                        </div>
                      )
                    })}
                  </div>
                  {presentHeaders === ALL_HEADERS.length ? (
                    <div className="border border-phosphor/40 bg-phosphor/5 px-3 py-3 text-sm text-phosphor">
                      all security headers present
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">
                      {presentHeaders}/{ALL_HEADERS.length} headers present
                    </p>
                  )}
                </section>

                {cert ? (
                  <section className="space-y-4 rounded-3xl border border-border bg-card p-4">
                    <div className="flex items-center justify-between gap-3">
                      <CardTitle className="text-sm">TLS Certificate</CardTitle>
                      {certBanner ? (
                        <Badge className={cn("text-sm", certBanner.className)}>
                          {certBanner.text}
                        </Badge>
                      ) : null}
                    </div>
                    <div className="space-y-3 text-sm text-muted-foreground">
                      <div>
                        <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                          Issuer
                        </div>
                        <div className="mt-1 text-sm text-foreground">{cert.issuer ?? "Unknown"}</div>
                      </div>
                      <div>
                        <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                          Valid from
                        </div>
                        <div className="mt-1 text-sm text-foreground">{formatDate(cert.valid_from)}</div>
                      </div>
                      <div>
                        <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                          Valid to
                        </div>
                        <div className="mt-1 text-sm text-foreground">{formatDate(cert.valid_to)}</div>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm text-foreground">
                          Days until expiry: {cert.days_until_expiry ?? "Unknown"}
                        </span>
                        {tlsOutdated ? (
                          <Badge variant="destructive" className="text-xs">
                            outdated TLS — upgrade to 1.2+
                          </Badge>
                        ) : null}
                      </div>
                      <div>
                        <div className="text-xs uppercase tracking-[0.18em] text-muted-foreground">
                          TLS version
                        </div>
                        <div className="mt-1 text-sm text-foreground">{cert.tls_version ?? "Unknown"}</div>
                      </div>
                      <div>
                        <button
                          type="button"
                          onClick={() =>
                            setShowSans((prev) => ({
                              ...prev,
                              [finding.url]: !sanOpen,
                            }))
                          }
                          className="inline-flex items-center gap-2 text-sm text-cyan transition hover:underline"
                        >
                          {sanOpen ? "hide SANs" : "show SANs"}
                          {sanOpen ? (
                            <ChevronUp className="h-4 w-4" />
                          ) : (
                            <ChevronDown className="h-4 w-4" />
                          )}
                        </button>
                        {sanOpen ? (
                          <div className="mt-3 space-y-2 rounded-2xl border border-border bg-background p-3 text-sm text-muted-foreground">
                            {cert.subject_alt_names && cert.subject_alt_names.length ? (
                              <ul className="list-disc space-y-1 pl-5">
                                {cert.subject_alt_names.map((san) => (
                                  <li key={san}>{san}</li>
                                ))}
                              </ul>
                            ) : (
                              <div>No Subject Alternative Names found.</div>
                            )}
                          </div>
                        ) : null}
                      </div>
                    </div>
                  </section>
                ) : null}
              </div>
            </CardContent>
          </Card>
        )
      })}

      {httpFindings.length > 5 ? (
        <div className="flex justify-center">
          <button
            type="button"
            onClick={() => setShowAll((current) => !current)}
            className="inline-flex items-center gap-2 border border-border px-3 py-1.5 text-sm text-phosphor-dim transition hover:border-phosphor/50 hover:text-phosphor"
          >
            {showAll ? "show less" : `show ${httpFindings.length - 3} more`}
            {showAll ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        </div>
      ) : null}
    </div>
  )
}

export default HttpPanel
