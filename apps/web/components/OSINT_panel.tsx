/**
 * components/OSINTPanel.tsx
 * -------------------------
 * Displays OSINT and DNS findings in the "OSINT & DNS" tab.
 * Shown in app/scan/[id]/page.tsx inside the Tabs component.
 *
 * PROPS:
 *   osint: OSINTResult | null
 *     Contains: whois, shodan_ports, shodan_org, shodan_country,
 *               certificates, subdomains_from_certs
 *   dnsRecords: DNSRecord[]
 *     List of DNS records: { record_type, name, value, ttl }
 *   subdomains: SubdomainResult[]
 *     List of discovered subdomains: { subdomain, ip_address, is_different_ip }
 *
 * LAYOUT — three sections stacked vertically:
 *
 *   SECTION 1: WHOIS (Card)
 *     Grid of labeled fields:
 *       Registrar | Registrant Org | Created | Expires | Name Servers | Country
 *     If osint or osint.whois is null: show "WHOIS data unavailable".
 *     If whois.is_expired is true: show a red warning badge "DOMAIN EXPIRED"
 *     next to the expiry date — expired domains are a takeover risk.
 *
 *   SECTION 2: DNS Records (Card with Table)
 *     Table columns: Type | Name | Value | TTL
 *     Group rows by record_type — show all A records together, then MX etc.
 *     Highlight any TXT records that contain "spf" or "dkim" — these are
 *     important security records. Show a green checkmark if SPF is present,
 *     red warning if absent (email spoofing risk).
 *
 *   SECTION 3: Subdomains discovered (Card)
 *     Two sub-sections side by side:
 *
 *     Left — "From DNS brute-force" (subdomains prop):
 *       List each subdomain with its resolved IP.
 *       Flag any where is_different_ip is true with a yellow badge
 *       "Different IP" — these are worth investigating.
 *
 *     Right — "From certificate logs" (osint.subdomains_from_certs):
 *       List of subdomains found in certificate transparency logs.
 *       These are historically issued certs — may reveal old/forgotten
 *       subdomains that are no longer active but still interesting.
 *
 *     If both lists are empty: "No subdomains discovered"
 *
 *   SECTION 4: Shodan data (Card) — only shown if shodan data is present:
 *     Org, Country, ports Shodan has seen, any CVEs Shodan flagged.
 *     Add a note: "Data from Shodan's last scan — may not reflect current state"
 *
 * EMPTY STATE:
 *   If osint is null and dnsRecords is empty:
 *   "OSINT data unavailable — check your API keys in .env"
 *
 * SHADCN COMPONENTS USED:
 *   Card, CardHeader, CardContent, CardTitle
 *   Table, TableHeader, TableRow, TableHead, TableBody, TableCell
 *   Badge, Separator
 *
 * NOTE:
 *   This is a display-only component. No "use client" needed unless
 *   you add interactive filtering. All data comes via props.
 */