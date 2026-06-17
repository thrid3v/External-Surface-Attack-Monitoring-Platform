# EASM — External Attack Surface Management

EASM discovers, inventories, and assesses an organization's internet-facing
attack surface. It combines active reconnaissance, passive intelligence, web &
TLS auditing, vulnerability enrichment, and risk scoring into a single
report — and turns one-off scans into continuous monitoring with scheduling,
change tracking, and alerts, surfaced through a dark "security operations
console" UI.

Scans run as asynchronous Celery tasks through a modular pipeline; results are
persisted to PostgreSQL and rendered live in a Next.js dashboard.

---

## Features

**Discovery & recon**
- 🔍 Port scanning & service/version fingerprinting (nmap)
- 🌐 DNS enumeration (A/AAAA/MX/TXT/NS/CNAME), subdomain brute-forcing, **zone-transfer (AXFR) detection**
- 🏷️ Subdomain discovery unified from brute-force **and** Certificate Transparency (crt.sh)
- 📜 WHOIS intelligence · 🔎 Shodan integration · 🔐 crt.sh certificate analysis

**Vulnerability detection**
- 🚨 **CPE-based CVE matching** (version-aware NVD lookup for common products) with keyword fallback
- 🛡️ Web exposure checks: exposed `.git`/`.env`/backups, `server-status`, `phpinfo`, actuator, swagger, directory listing, **CORS misconfig**, cookie flags, clickjacking
- 🔒 TLS audit: deprecated TLS 1.0/1.1, self-signed / expired / hostname-mismatch certs
- 🪝 **Subdomain takeover** detection (dangling CNAMEs + unclaimed S3/GitHub Pages/Heroku/Azure/…)
- 📧 Email posture: SPF & DMARC grading (spoofability)
- 🧪 **Nuclei** template scanning (thousands of community templates; optional binary)
- 📊 Unified **Findings** model + 0–100 risk scoring & severity breakdown

**Monitoring & automation**
- ⏱️ Recurring/scheduled scans (Celery beat dispatcher)
- 🔁 Scan-to-scan **diffing** — new/resolved CVEs, opened/closed ports, risk delta
- 🔔 Change **alerts** on new high/critical findings or rising risk
- 📈 Per-target risk-over-time history

**Platform**
- 🔐 Google sign-in (NextAuth) with **per-user scan isolation**; the API is locked down behind a Backend-For-Frontend
- 💻 Dark ops-console dashboard (Next.js 16, React 19, Tailwind 4, recharts)
- ⚡ Async processing (Celery + Redis) · 🗄️ PostgreSQL persistence · 🧬 Alembic migrations
- 🚀 FastAPI backend

---

## Architecture

```text
┌──────────────┐   BFF proxy (auth + identity)   ┌──────────────┐
│  Next.js web │ ───────────────────────────────▶│  FastAPI API │
│ (dashboard)  │   /api/easm/* → /api/*           │  (routers)   │
└──────────────┘                                  └──────┬───────┘
   Google OAuth                                          │ enqueue
   (NextAuth)                                            ▼
                                                  ┌──────────────┐
                          schedules (beat) ──────▶│ Celery worker│
                                                  │  run_scan    │
                                                  └──────┬───────┘
                                                         │ imports
                                                         ▼
                                              packages/scanner_core
   PostgreSQL ◀── results/scans/schedules/alerts ──┘   Redis (broker/result)
```

### Scan pipeline (per `MODULE_ORDER`)

```text
port_scanner → cve_lookup → dns_enum → osint_fetcher → service_probe
            → web_audit → takeover_check → email_audit → nuclei_scan
                                   │
                                   ▼
                            report_gen  →  ScanReport
        (CVEs + Findings → severity summary + 0–100 risk score)
```

Each module degrades gracefully: a failure (or a missing optional dependency
like a Shodan/NVD key or the nuclei binary) is recorded per-module and the scan
still completes with partial results.

---

## Scanner modules (`packages/scanner_core/`)

| Module             | Purpose                                                                    |
| ------------------ | -------------------------------------------------------------------------- |
| `port_scanner.py`  | Discover open ports + service/version (nmap `-sV`)                          |
| `cve_lookup.py`    | Version-aware CVE matching via CPE (NVD), keyword fallback, dedup + capping |
| `dns_enum.py`      | DNS records, subdomain brute-force, zone-transfer (AXFR) check             |
| `osint_fetcher.py` | WHOIS, Shodan, crt.sh certificates & cert-derived subdomains               |
| `service_probe.py` | HTTP fingerprint/headers + **TLS audit** (weak protocols, cert problems)   |
| `web_audit.py`     | Exposed files/paths, dir listing, CORS, cookie flags, clickjacking         |
| `takeover.py`      | Subdomain takeover (dangling CNAME / unclaimed service)                     |
| `email_audit.py`   | SPF & DMARC grading                                                         |
| `nuclei_scan.py`   | ProjectDiscovery Nuclei templates (optional binary)                        |
| `report_gen.py`    | Aggregate CVEs + Findings, severity summary, risk score                    |
| `models.py`        | Shared Pydantic models (incl. `Finding`, `ScanReport`)                     |

---

## Tech stack

- **Frontend:** Next.js 16, React 19, TypeScript, Tailwind CSS 4, recharts, NextAuth
- **Backend:** FastAPI, Celery (+ beat), Redis, PostgreSQL, SQLAlchemy, Alembic
- **Recon/security:** nmap, Nuclei, Shodan, WHOIS, crt.sh, httpx, dnspython
- **Infra:** Docker / Docker Compose

---

## Prerequisites

- **Python 3.11+** and **Node.js 20+**
- **Docker** (for PostgreSQL + Redis)
- **nmap** on `PATH` — **required** for port scanning
- **nuclei** on `PATH` — **optional**, enables template scanning ([install](https://github.com/projectdiscovery/nuclei))

---

## Setup

### 1. Clone

```bash
git clone https://github.com/thrid3v/External-Surface-Attack-Monitoring-Platform.git easm
cd easm
```

### 2. Start PostgreSQL + Redis

```bash
docker compose up -d        # Postgres :5432, Redis :6379
```

### 3. Backend config

Copy the example and edit `apps/api/.env`:

```bash
cp .env.example apps/api/.env
```

| Variable              | Required | Notes                                                            |
| --------------------- | -------- | ---------------------------------------------------------------- |
| `DATABASE_URL`        | ✅       | PostgreSQL connection string                                     |
| `REDIS_URL`           | ✅       | Celery broker + result backend                                   |
| `INTERNAL_API_SECRET` | ✅       | Shared secret with the web BFF (API fails closed without it)     |
| `FRONTEND_URL`        | ✅       | Allowed CORS origin(s), comma-separated                          |
| `SHODAN_API_KEY`      | ⬜       | Optional — enables Shodan enrichment                             |
| `NVD_API_KEY`         | ⬜       | Optional — raises NVD rate limit (5→50 req / 30s)                |
| `SCAN_TIMEOUT`        | ⬜       | Per-scan wall-clock budget in seconds (default 300)             |
| `SMTP_HOST` … `SMTP_FROM` | ⬜   | Email-alert transport. Blank `SMTP_HOST` disables email (webhooks still work). Per-user routing lives in **Settings → Notifications** |

### 4. Backend install + migrations

```bash
cd apps/api
python -m venv venv
# Windows:        venv\Scripts\Activate.ps1
# Linux/macOS:    source venv/bin/activate

pip install -r requirements.txt   # also installs scanner_core (editable) — no PYTHONPATH needed
alembic upgrade head              # creates scans / schedules / alerts tables
```

### 5. Run the backend (three processes)

```bash
# Terminal A — API
uvicorn main:app --reload --port 8000

# Terminal B — Celery worker  (Windows requires the solo pool)
celery -A workers.scan_worker worker --loglevel=info -P solo
#   Linux/macOS: celery -A workers.scan_worker worker --loglevel=info

# Terminal C — Celery beat (drives recurring scans + the stuck-scan reaper)
#   Windows: run beat as its own process (the worker's -B flag is unsupported there)
celery -A workers.scan_worker beat --loglevel=info
```

> Out-of-band alert delivery (email + webhook) is configured per user in the web
> UI under **Settings → Notifications**. A change-detection alert fans out to the
> user's enabled channels whenever a re-scan surfaces new high/critical findings
> or a higher risk score.

### 6. Frontend config

Create `apps/web/.env.local`:

```env
API_URL=http://127.0.0.1:8000
INTERNAL_API_SECRET=<same value as apps/api/.env>
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=<long random string>
GOOGLE_CLIENT_ID=<your google oauth client id>
GOOGLE_CLIENT_SECRET=<your google oauth client secret>
```

**Google OAuth setup** (Google Cloud Console → APIs & Services → Credentials → OAuth client ID, type *Web application*):
- Authorized redirect URI: `http://localhost:3000/api/auth/callback/google`
- If the consent screen is in *Testing*, add your Google account as a **Test user**

### 7. Run the frontend

```bash
cd apps/web
npm install
npm run dev                 # http://localhost:3000
```

### 8. (Optional) Enable Nuclei

```bash
# Windows
winget install ProjectDiscovery.Nuclei
# or download a release binary and put it on PATH
```
Once `nuclei` is on `PATH`, the `nuclei_scan` module activates automatically.

---

## Using the app

1. Open **http://localhost:3000** and sign in with Google.
2. On the **Dashboard**, enter a target, pick a **port profile** (Common / Top 1000 / Full) and optionally toggle **modules**, then scan. (`scanme.nmap.org` is Nmap's legal test host.)
3. The **report** shows the risk gauge, severity breakdown, a zone-transfer banner, the **Findings** tab (misconfig/exposure/TLS/takeover/email/nuclei), CVEs, ports, OSINT/DNS, HTTP, and a **"Changes since last scan"** diff once a target has ≥2 scans.
4. **Targets** lists every target with risk-over-time history; **Schedules** manages recurring scans; **Alerts** surfaces new risk from re-scans.

Each scan request must include `i_own_this_target: true` — a legal acknowledgment that you are authorized to scan the target.

---

## API reference

All endpoints are under `/api` and require authentication. In normal use the
Next.js BFF (`/api/easm/*`) injects `X-Internal-Secret` and `X-User-Email`;
direct calls must supply both headers. Scans/targets/schedules/alerts are scoped
to the acting user.

| Method & path                          | Description                              |
| -------------------------------------- | ---------------------------------------- |
| `POST /api/scans`                      | Queue a scan (`target`, `profile`/`port_range`, `modules`, `i_own_this_target`) |
| `GET /api/scans`                       | List the user's recent scans             |
| `GET /api/scans/{id}`                  | Full report (or status if not complete)  |
| `GET /api/scans/{id}/status`           | Live status + current module             |
| `GET /api/scans/{id}/diff`             | Diff vs the previous completed scan      |
| `DELETE /api/scans/{id}`               | Delete a scan                            |
| `GET /api/targets`                     | One summary row per target               |
| `GET /api/targets/{target}/history`    | All scans for a target                   |
| `GET /api/targets/{target}/latest`     | Latest completed report for a target     |
| `POST/GET /api/schedules`              | Create / list recurring scans            |
| `POST /api/schedules/{id}/toggle`      | Enable/pause a schedule                  |
| `DELETE /api/schedules/{id}`           | Delete a schedule                        |
| `GET /api/alerts`                      | List alerts (`?unread_only=true`)        |
| `POST /api/alerts/{id}/read` · `/read-all` | Mark read                            |

Interactive docs: `http://localhost:8000/docs`.

---

## Testing

```bash
pytest packages/scanner_core/tests/
```

## Database migrations

```bash
cd apps/api
alembic upgrade head
alembic revision --autogenerate -m "description"
```

---

## Concepts & glossary

<details>
<summary>Ports, services, CVE/CVSS, DNS, subdomains, TLS, WHOIS, OSINT, security headers</summary>

**Ports** — a door into a system; open ports expose internet-accessible services (22 SSH, 80 HTTP, 443 HTTPS, 3306 MySQL).

**Services** — software listening on a port (Apache, nginx, OpenSSH, MySQL). Version detection matters because vulnerabilities are version-specific.

**CVE** — a publicly documented vulnerability (e.g. `CVE-2021-41773`) with description, severity, CVSS score, and references.

**CVSS** — severity 0.0–10.0: 9.0–10.0 Critical · 7.0–8.9 High · 4.0–6.9 Medium · 0.1–3.9 Low · 0.0 None.

**DNS records** — A (IPv4), AAAA (IPv6), MX (mail), TXT (SPF/verification), NS (name servers), CNAME (alias).

**Subdomains** — child domains (api/dev/staging/vpn.example.com); forgotten ones become attack vectors. EASM finds them via brute-force and certificate transparency.

**TLS certificates** — enable HTTPS; their SANs often reveal more infrastructure. EASM flags weak protocols and expired/self-signed/mismatched certs.

**WHOIS** — domain registration/ownership (registrar, org, dates, name servers, country).

**OSINT** — publicly available intel (WHOIS, Shodan, crt.sh, public DNS) gathered passively.

**Security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy; missing headers indicate weak posture.

</details>

---

## Roadmap

- Cloud exposure checks (open S3 buckets, unauthenticated Redis/Mongo/Elasticsearch)
- Secrets-in-JavaScript / leaked API key scanning
- DKIM selector probing
- Censys integration & threat-intel enrichment
- PDF report export & multi-tenant org support

---

## Key constraints

- **Scan authorization:** the API requires `i_own_this_target: true`.
- **Windows Celery:** use the `-P solo` pool (no fork support).
- **nmap is required**; **nuclei is optional** (auto-detected on PATH).
- The API is fail-closed: it rejects requests without a valid `INTERNAL_API_SECRET`.

---

## Disclaimer

For educational, research, and **authorized** security assessment only. Only
scan systems you have explicit permission to test. Unauthorized scanning may
violate laws, regulations, or policies.

## License

MIT
