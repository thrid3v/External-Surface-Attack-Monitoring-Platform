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
  source?: string
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

export interface Finding {
  title: string
  severity: string
  category: string
  description?: string
  target?: string | null
  evidence?: string | null
  remediation?: string | null
  source?: string
  references?: string[]
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
  zone_transfer_vulnerable?: boolean
  zone_transfer_records?: string[]
  osint: OSINTResult | null
  http_findings: HttpFinding[]
  findings: Finding[]
  top_findings: CVEResult[]
  started_at: string | null
  completed_at: string | null
  scan_duration_seconds: number | null
  modules_run: string[]
  errors: Record<string, string>
}

export interface DiffCve {
  cve_id: string
  severity: string
  cvss_score: number | null
}

export interface DiffResult {
  scan_id: string
  target: string
  compared_to: string | null
  risk_delta: number | null
  current_risk: number | null
  previous_risk: number | null
  new_cves: DiffCve[]
  resolved_cves: DiffCve[]
  opened_ports: number[]
  closed_ports: number[]
}

export interface Schedule {
  id: string
  target: string
  port_range: string
  profile: string | null
  modules: string[] | null
  interval_minutes: number
  enabled: boolean
  next_run_at: string | null
  last_run_at: string | null
  created_at: string | null
}

export interface Alert {
  id: string
  target: string
  scan_id: string | null
  type: string
  severity: string
  message: string
  read: boolean
  created_at: string | null
}

export interface NotificationSettings {
  owner_email: string
  email_enabled: boolean
  email_address: string | null
  webhook_enabled: boolean
  webhook_url: string | null
  min_severity: string
}
