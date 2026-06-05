"use client"

import * as React from "react"
import { Check, ExternalLink, ChevronDown, ChevronUp, X } from "lucide-react"

import { Badge } from "./ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card"
import { cn } from "@/lib/utils"

const ALL_HEADERS = [
  "Content-Security-Policy",
  "X-Frame-Options",
  "Strict-Transport-Security",
  "X-Content-Type-Options",
  "Referrer-Policy",
  "Permissions-Policy",
] as const

export interface CertInfo {
  issuer?: string | null
  valid_from?: string | null
  valid_to?: string | null
  days_until_expiry?: number | null
  tls_version?: string | null
  is_expired?: boolean
  sans?: string[] | null
}

export interface HttpFinding {
  url: string
  status_code: number
  server_header?: string | null
  powered_by?: string | null
  cms_detected?: string | null
  missing_headers: string[]
  cert?: CertInfo | null
}

function statusBadgeProps(statusCode: number) {
  if (statusCode === 200) {
    return {
      className:
        "bg-emerald-100 text-emerald-900 border border-emerald-200",
    }
  }

  if (statusCode === 301 || statusCode === 302) {
    return {
      className: "bg-sky-100 text-sky-900 border border-sky-200",
    }
  }

  if (statusCode === 403) {
    return {
      className: "bg-amber-100 text-amber-900 border border-amber-200",
    }
  }

  if (statusCode === 500) {
    return {
      variant: "destructive" as const,
    }
  }

  return {
    className: "bg-slate-100 text-slate-900 border border-slate-200",
  }
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
    return {
      text: "Certificate EXPIRED",
      className: "bg-destructive/10 text-destructive border border-destructive/20",
    }
  }

  if (cert.days_until_expiry !== null && cert.days_until_expiry !== undefined && cert.days_until_expiry < 30) {
    return {
      text: `Expires in ${cert.days_until_expiry} days`,
      className: "bg-amber-100 text-amber-950 border border-amber-200",
    }
  }

  return {
    text: "Valid",
    className: "bg-emerald-100 text-emerald-900 border border-emerald-200",
  }
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
              <Badge className="rounded-full px-3 py-1 text-sm font-medium" {...statusBadgeProps(finding.status_code)}>
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
                      <Badge className="rounded-full px-2 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-amber-900 border border-amber-200 bg-amber-100">
                        CMS detected
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
                        <div className="rounded-2xl border border-amber-200 bg-amber-100 px-3 py-2 text-sm text-amber-950">
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
                          <span className="inline-flex items-center gap-1 rounded-full px-2 py-1 text-xs font-semibold">
                            {present ? (
                              <Check className="h-3.5 w-3.5 text-emerald-700" />
                            ) : (
                              <X className="h-3.5 w-3.5 text-destructive" />
                            )}
                            <span className={present ? "text-emerald-700" : "text-destructive"}>
                              {present ? "Present" : "Missing"}
                            </span>
                          </span>
                        </div>
                      )
                    })}
                  </div>
                  {presentHeaders === ALL_HEADERS.length ? (
                    <div className="rounded-2xl border border-emerald-200 bg-emerald-100 px-3 py-3 text-sm text-emerald-900">
                      All security headers present
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
                        <Badge className={cn("rounded-full px-3 py-1 text-sm font-medium", certBanner.className)}>
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
                          <Badge variant="destructive" className="rounded-full px-2 py-1 text-xs font-semibold uppercase">
                            Outdated TLS — upgrade to TLS 1.2+
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
                          className="inline-flex items-center gap-2 text-sm font-medium text-primary transition hover:text-primary/80"
                        >
                          {sanOpen ? "Hide SANs" : "Show SANs"}
                          {sanOpen ? (
                            <ChevronUp className="h-4 w-4" />
                          ) : (
                            <ChevronDown className="h-4 w-4" />
                          )}
                        </button>
                        {sanOpen ? (
                          <div className="mt-3 space-y-2 rounded-2xl border border-border bg-background p-3 text-sm text-muted-foreground">
                            {cert.sans && cert.sans.length ? (
                              <ul className="list-disc space-y-1 pl-5">
                                {cert.sans.map((san) => (
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
            className="inline-flex items-center gap-2 rounded-full border border-border bg-background px-4 py-2 text-sm font-medium text-primary transition hover:bg-muted"
          >
            {showAll ? "Show less" : `Show ${httpFindings.length - 3} more`}
            {showAll ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        </div>
      ) : null}
    </div>
  )
}

export default HttpPanel
