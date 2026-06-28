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
<<<<<<< HEAD
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { CheckCircle2, AlertTriangle } from "lucide-react";

// ---------------------------------------------------------------------------
// Local interfaces — scoped to fields documented in the specification only
// ---------------------------------------------------------------------------

interface WHOISData {
  registrar: string | null;
  registrant_org: string | null;
  created: string | null;
  expires: string | null;
  name_servers: string[] | null;
  country: string | null;
  is_expired: boolean;
}

interface OSINTResult {
  whois: WHOISData | null;
  shodan_ports: number[] | null;
  shodan_org: string | null;
  shodan_country: string | null;
  certificates: string[] | null;
  subdomains_from_certs: string[] | null;
}

interface DNSRecord {
  record_type: string;
  name: string;
  value: string;
  ttl: number;
}

interface SubdomainResult {
  subdomain: string;
  ip_address: string | null;
  is_different_ip: boolean;
}

interface OSINTPanelProps {
  osint: OSINTResult | null;
  dnsRecords: DNSRecord[];
  subdomains: SubdomainResult[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(value: string | null): string {
  if (!value) return "—";
  const d = new Date(value);
  return isNaN(d.getTime()) ? value : d.toLocaleDateString(undefined, { dateStyle: "medium" });
}

function nullish(value: string | null | undefined): string {
  return value ?? "—";
}

function groupByRecordType(records: DNSRecord[]): Map<string, DNSRecord[]> {
  const map = new Map<string, DNSRecord[]>();
  for (const record of records) {
    const group = map.get(record.record_type) ?? [];
    group.push(record);
    map.set(record.record_type, group);
  }
  return map;
}

function hasSpf(records: DNSRecord[]): boolean {
  return records.some(
    (r) => r.record_type === "TXT" && r.value.toLowerCase().includes("spf")
  );
}

function hasDkim(records: DNSRecord[]): boolean {
  return records.some(
    (r) => r.record_type === "TXT" && r.value.toLowerCase().includes("dkim")
  );
}

function isSecurityTxt(record: DNSRecord): boolean {
  const v = record.value.toLowerCase();
  return record.record_type === "TXT" && (v.includes("spf") || v.includes("dkim"));
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function WhoisField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      <span className="text-sm text-foreground">{children}</span>
    </div>
  );
}

function WhoisSection({ whois }: { whois: WHOISData | null }) {
  if (!whois) {
    return (
      <p className="text-sm text-muted-foreground">WHOIS data unavailable.</p>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-x-8 gap-y-4 sm:grid-cols-3">
      <WhoisField label="Registrar">{nullish(whois.registrar)}</WhoisField>
      <WhoisField label="Registrant Org">{nullish(whois.registrant_org)}</WhoisField>
      <WhoisField label="Country">{nullish(whois.country)}</WhoisField>
      <WhoisField label="Created">{formatDate(whois.created)}</WhoisField>
      <WhoisField label="Expires">
        <span className="flex items-center gap-2">
          {formatDate(whois.expires)}
          {whois.is_expired && (
            <Badge className="bg-red-100 text-red-700 border-red-200 text-xs font-semibold">
              DOMAIN EXPIRED
            </Badge>
          )}
        </span>
      </WhoisField>
      <WhoisField label="Name Servers">
        {whois.name_servers && whois.name_servers.length > 0 ? (
          <ul className="flex flex-col gap-0.5">
            {whois.name_servers.map((ns) => (
              <li key={ns} className="font-mono text-xs">
                {ns}
              </li>
            ))}
          </ul>
        ) : (
          "—"
        )}
      </WhoisField>
    </div>
  );
}

function DNSSection({ records }: { records: DNSRecord[] }) {
  if (records.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">No DNS records found.</p>
    );
  }

  const grouped = groupByRecordType(records);
  const spfPresent = hasSpf(records);
  const dkimPresent = hasDkim(records);

  // Flatten while preserving record_type grouping order
  const sorted: DNSRecord[] = [];
  grouped.forEach((group) => sorted.push(...group));

  return (
    <div className="flex flex-col gap-4">
      {/* SPF / DKIM security indicator */}
      <div className="flex flex-wrap gap-3">
        <span className="flex items-center gap-1.5 text-sm">
          {spfPresent ? (
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          ) : (
            <AlertTriangle className="h-4 w-4 text-red-500" />
          )}
          <span className={spfPresent ? "text-green-700" : "text-red-600"}>
            SPF {spfPresent ? "present" : "absent — email spoofing risk"}
          </span>
        </span>
        <span className="flex items-center gap-1.5 text-sm">
          {dkimPresent ? (
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          ) : (
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
          )}
          <span className={dkimPresent ? "text-green-700" : "text-yellow-700"}>
            DKIM {dkimPresent ? "present" : "not detected"}
          </span>
        </span>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-24">Type</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Value</TableHead>
              <TableHead className="w-24 text-right">TTL</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sorted.map((record, idx) => (
              <TableRow
                key={idx}
                className={isSecurityTxt(record) ? "bg-green-50" : undefined}
              >
                <TableCell>
                  <Badge variant="outline" className="font-mono text-xs">
                    {record.record_type}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">{record.name}</TableCell>
                <TableCell className="max-w-xs break-all font-mono text-xs">
                  {record.value}
                </TableCell>
                <TableCell className="text-right text-xs text-muted-foreground">
                  {record.ttl}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

function SubdomainsSection({
  subdomains,
  certsSubdomains,
}: {
  subdomains: SubdomainResult[];
  certsSubdomains: string[];
}) {
  const bothEmpty = subdomains.length === 0 && certsSubdomains.length === 0;

  if (bothEmpty) {
    return (
      <p className="text-sm text-muted-foreground">No subdomains discovered.</p>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
      {/* Left — DNS brute-force */}
      <div className="flex flex-col gap-2">
        <h4 className="text-sm font-semibold text-foreground">
          From DNS brute-force
        </h4>
        {subdomains.length === 0 ? (
          <p className="text-sm text-muted-foreground">None found.</p>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {subdomains.map((s, idx) => (
              <li key={idx} className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-mono text-xs text-foreground">
                  {s.subdomain}
                </span>
                {s.ip_address && (
                  <span className="text-xs text-muted-foreground">
                    {s.ip_address}
                  </span>
                )}
                {s.is_different_ip && (
                  <Badge className="bg-yellow-100 text-yellow-800 border-yellow-200 text-xs">
                    Different IP
                  </Badge>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>


      {/* Right — Certificate logs */}
      <div className="flex flex-col gap-2">
        <h4 className="text-sm font-semibold text-foreground">
          From certificate logs
        </h4>
        {certsSubdomains.length === 0 ? (
          <p className="text-sm text-muted-foreground">None found.</p>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {certsSubdomains.map((sub, idx) => (
              <li key={idx} className="font-mono text-xs text-foreground">
                {sub}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function ShodanSection({ osint }: { osint: OSINTResult }) {
  const hasShodan =
    osint.shodan_org || osint.shodan_country || (osint.shodan_ports && osint.shodan_ports.length > 0);

  if (!hasShodan) return null;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">Shodan Intelligence</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          <WhoisField label="Organisation">{nullish(osint.shodan_org)}</WhoisField>
          <WhoisField label="Country">{nullish(osint.shodan_country)}</WhoisField>
          {osint.shodan_ports && osint.shodan_ports.length > 0 && (
            <WhoisField label="Open ports seen">
              <span className="flex flex-wrap gap-1">
                {osint.shodan_ports.map((port) => (
                  <Badge
                    key={port}
                    variant="outline"
                    className="font-mono text-xs"
                  >
                    {port}
                  </Badge>
                ))}
              </span>
            </WhoisField>
          )}
        </div>
        <p className="text-xs text-muted-foreground">
          Data from Shodan&apos;s last scan — may not reflect current state.
        </p>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function OSINTPanel({ osint, dnsRecords, subdomains }: OSINTPanelProps) {
  if (!osint && dnsRecords.length === 0) {
    return (
      <div className="flex items-center justify-center rounded-lg border border-dashed p-12">
        <p className="text-sm text-muted-foreground">
          OSINT data unavailable — check your API keys in <code className="font-mono">.env</code>
        </p>
      </div>
    );
  }

  const certsSubdomains = osint?.subdomains_from_certs ?? [];

  return (
    <div className="flex flex-col gap-6">
      {/* Section 1 — WHOIS */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">WHOIS</CardTitle>
        </CardHeader>
        <CardContent>
          <WhoisSection whois={osint?.whois ?? null} />
        </CardContent>
      </Card>

      {/* Section 2 — DNS Records */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">DNS Records</CardTitle>
        </CardHeader>
        <CardContent>
          <DNSSection records={dnsRecords} />
        </CardContent>
      </Card>

      {/* Section 3 — Subdomains */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Subdomains Discovered</CardTitle>
        </CardHeader>
        <CardContent>
          <SubdomainsSection
            subdomains={subdomains}
            certsSubdomains={certsSubdomains}
          />
        </CardContent>
      </Card>

      {/* Section 4 — Shodan (conditional) */}
      {osint && <ShodanSection osint={osint} />}
    </div>
  );
=======
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
>>>>>>> bb03bb484d7ac7dbf46dee02859d4174db14db56
}
