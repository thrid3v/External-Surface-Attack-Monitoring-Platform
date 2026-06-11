export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"

export interface CVEResult {
  cve_id: string
  description: string
  cvss_score: number | null
  cvss_version: string | null
  severity: Severity
  published_date: string | null
  references: string[]
}

export interface PortResult {
  port: number
  protocol: string
  service: string | null
  product?: string | null
  version?: string | null
  banner?: string | null
  cves?: CVEResult[]
}

export interface DNSRecord {
  record_type: string
  name: string
  value: string
  ttl?: number | null
}

export interface SubdomainResult {
  subdomain: string
  ip_address?: string | null
  is_different_ip?: boolean
}

export interface WHOISInfo {
  registrar?: string | null
  registrant_org?: string | null
  created_date?: string | null
  expiry_date?: string | null
  is_expired?: boolean
  name_servers?: string[]
  country?: string | null
}

export interface CertInfo {
  domain: string
  issuer?: string | null
  valid_from?: string | null
  valid_to?: string | null
  days_until_expiry?: number | null
  is_expired?: boolean
  tls_version?: string | null
  subject_alt_names?: string[]
}

export interface OSINTResult {
  whois?: WHOISInfo | null
  shodan_ports?: number[]
  shodan_vulns?: string[]
  shodan_org?: string | null
  shodan_country?: string | null
  certificates?: CertInfo[]
  subdomains_from_certs?: string[]
}

export interface HttpFinding {
  url: string
  status_code?: number | null | undefined
  server_header?: string | null
  powered_by?: string | null
  cms_detected?: string | null
  missing_headers: string[]
  cert?: CertInfo | null
}

export interface ScanReport {
  scan_id: string
  target: string
  status: "pending" | "running" | "complete" | "failed"
  risk_score: number | null
  risk_label: string | null
  severity_summary: Record<string, number>
  ports: PortResult[]
  cves: CVEResult[]
  dns_records: DNSRecord[]
  subdomains: SubdomainResult[]
  osint: OSINTResult | null
  http_findings: HttpFinding[]
  top_findings: CVEResult[]
  started_at: string | null
  completed_at: string | null
  scan_duration_seconds: number | null
  modules_run: string[]
  errors: Record<string, string>
}
