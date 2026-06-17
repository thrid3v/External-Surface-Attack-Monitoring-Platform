import { AlertTriangle, CheckCircle, XCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

interface WHOISInfo {
  registrar?: string | null
  registrant_org?: string | null
  created_date?: string | null
  expiry_date?: string | null
  is_expired?: boolean
  name_servers?: string[]
  country?: string | null
}

interface OSINTResult {
  whois?: WHOISInfo | null
  shodan_ports?: number[]
  shodan_vulns?: string[]
  shodan_org?: string | null
  shodan_country?: string | null
  certificates?: unknown[]
  subdomains_from_certs?: string[]
}

interface DNSRecord {
  record_type: string
  name: string
  value: string
  ttl?: number | null
}

interface SubdomainResult {
  subdomain: string
  ip_address?: string | null
  is_different_ip?: boolean
}

interface OSINTPanelProps {
  osint: OSINTResult | null
  dnsRecords: DNSRecord[]
  subdomains: SubdomainResult[]
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—"
  try {
    return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })
  } catch {
    return iso
  }
}

export default function OSINTPanel({ osint, dnsRecords, subdomains }: OSINTPanelProps) {
  const noData = !osint && dnsRecords.length === 0

  if (noData) {
    return (
      <Card className="rounded-3xl border border-border">
        <CardContent className="pt-6">
          <p className="text-sm text-muted-foreground">
            OSINT data unavailable — check your API keys in .env
          </p>
        </CardContent>
      </Card>
    )
  }

  // --- DNS grouping ---
  const recordOrder = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
  const grouped = dnsRecords.reduce<Record<string, DNSRecord[]>>((acc, r) => {
    ;(acc[r.record_type] ??= []).push(r)
    return acc
  }, {})
  const sortedTypes = [
    ...recordOrder.filter((t) => grouped[t]),
    ...Object.keys(grouped).filter((t) => !recordOrder.includes(t)),
  ]

  const txtRecords = grouped["TXT"] ?? []
  const hasSPF = txtRecords.some((r) => r.value.toLowerCase().includes("spf"))
  const hasDKIM = txtRecords.some((r) => r.value.toLowerCase().includes("dkim"))

  // --- Subdomains ---
  const certSubdomains = osint?.subdomains_from_certs ?? []
  const hasSubdomains = subdomains.length > 0 || certSubdomains.length > 0

  // --- Shodan ---
  const shodanPorts = osint?.shodan_ports ?? []
  const shodanVulns = osint?.shodan_vulns ?? []
  const showShodan = shodanPorts.length > 0 || !!osint?.shodan_org

  return (
    <div className="space-y-4">
      {/* WHOIS */}
      <Card className="rounded-3xl border border-border">
        <CardHeader>
          <CardTitle className="text-base">WHOIS</CardTitle>
        </CardHeader>
        <CardContent>
          {!osint?.whois ? (
            <p className="text-sm text-muted-foreground">WHOIS data unavailable</p>
          ) : (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3">
              {[
                { label: "Registrar",      value: osint.whois.registrar },
                { label: "Registrant Org", value: osint.whois.registrant_org },
                { label: "Country",        value: osint.whois.country },
                { label: "Created",        value: formatDate(osint.whois.created_date) },
                {
                  label: "Expires",
                  value: formatDate(osint.whois.expiry_date),
                  expired: osint.whois.is_expired,
                },
                {
                  label: "Name Servers",
                  value: (osint.whois.name_servers ?? []).join(", ") || null,
                },
              ].map(({ label, value, expired }) => (
                <div key={label}>
                  <dt className="text-xs text-muted-foreground">{label}</dt>
                  <dd className="mt-0.5 flex items-center gap-2 text-sm font-medium">
                    {value || "—"}
                    {expired && (
                      <Badge className="border-red/50 text-red">
                        domain expired
                      </Badge>
                    )}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </CardContent>
      </Card>

      {/* DNS Records */}
      {dnsRecords.length > 0 && (
        <Card className="rounded-3xl border border-border">
          <CardHeader className="flex flex-row items-center justify-between gap-4 pb-2">
            <CardTitle className="text-base">DNS Records</CardTitle>
            <div className="flex gap-2 text-xs">
              <span className="flex items-center gap-1">
                {hasSPF ? (
                  <CheckCircle className="h-3.5 w-3.5 text-phosphor" />
                ) : (
                  <XCircle className="h-3.5 w-3.5 text-red" />
                )}
                SPF
              </span>
              <span className="flex items-center gap-1">
                {hasDKIM ? (
                  <CheckCircle className="h-3.5 w-3.5 text-phosphor" />
                ) : (
                  <XCircle className="h-3.5 w-3.5 text-red" />
                )}
                DKIM
              </span>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-6 w-20">Type</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Value</TableHead>
                  <TableHead className="pr-6 w-20 text-right">TTL</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sortedTypes.flatMap((type) =>
                  (grouped[type] ?? []).map((record, i) => {
                    const isSecurity =
                      type === "TXT" &&
                      (record.value.toLowerCase().includes("spf") ||
                        record.value.toLowerCase().includes("dkim"))
                    return (
                      <TableRow key={`${type}-${i}`} className={isSecurity ? "bg-phosphor/5" : undefined}>
                        <TableCell className="pl-6 font-mono text-xs font-semibold text-muted-foreground">
                          {type}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{record.name}</TableCell>
                        <TableCell className="max-w-sm break-all font-mono text-xs">
                          {record.value}
                        </TableCell>
                        <TableCell className="pr-6 text-right font-mono text-xs text-muted-foreground">
                          {record.ttl ?? "—"}
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Subdomains */}
      <Card className="rounded-3xl border border-border">
        <CardHeader>
          <CardTitle className="text-base">Subdomains</CardTitle>
        </CardHeader>
        <CardContent>
          {!hasSubdomains ? (
            <p className="text-sm text-muted-foreground">No subdomains discovered</p>
          ) : (
            <div className="grid gap-6 sm:grid-cols-2">
              <div>
                <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  From DNS brute-force
                </p>
                {subdomains.length === 0 ? (
                  <p className="text-sm text-muted-foreground">None found</p>
                ) : (
                  <ul className="space-y-2">
                    {subdomains.map((s) => (
                      <li key={s.subdomain} className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm">{s.subdomain}</span>
                        {s.ip_address && (
                          <span className="font-mono text-xs text-muted-foreground">{s.ip_address}</span>
                        )}
                        {s.is_different_ip && (
                          <Badge className="border-yellow/50 text-yellow">
                            different ip
                          </Badge>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              <div>
                <p className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  From certificate logs
                </p>
                {certSubdomains.length === 0 ? (
                  <p className="text-sm text-muted-foreground">None found</p>
                ) : (
                  <ul className="space-y-2">
                    {certSubdomains.map((s) => (
                      <li key={s} className="font-mono text-sm">{s}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Shodan */}
      {showShodan && (
        <Card className="rounded-3xl border border-border">
          <CardHeader>
            <CardTitle className="text-base">Shodan Intelligence</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <dl className="grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4">
              <div>
                <dt className="text-xs text-muted-foreground">Organisation</dt>
                <dd className="mt-0.5 text-sm font-medium">{osint?.shodan_org || "—"}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Country</dt>
                <dd className="mt-0.5 text-sm font-medium">{osint?.shodan_country || "—"}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Open Ports</dt>
                <dd className="mt-0.5 font-mono text-sm font-medium">
                  {shodanPorts.length > 0 ? shodanPorts.join(", ") : "—"}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">CVEs flagged</dt>
                <dd className="mt-0.5 text-sm font-medium">
                  {shodanVulns.length > 0 ? (
                    <span className="flex flex-wrap gap-1">
                      {shodanVulns.map((v) => (
                        <Badge key={v} className="border-red/50 font-mono text-red">
                          {v}
                        </Badge>
                      ))}
                    </span>
                  ) : (
                    "None"
                  )}
                </dd>
              </div>
            </dl>
            <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <AlertTriangle className="h-3.5 w-3.5" />
              Data from Shodan&apos;s last scan — may not reflect current state
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
