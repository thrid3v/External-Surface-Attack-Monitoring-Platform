# EASM — External Attack Surface Management

EASM discovers, inventories, and assesses an organization's internet-facing **attack surface**.
You give it a domain or IP you own; it runs a modular recon-and-assessment pipeline as an async
job and returns a structured, **risk-scored** report — open ports and service versions, matching
CVEs, DNS and subdomains, OSINT, HTTP/TLS posture, web exposures, subdomain-takeover and email
(SPF/DMARC) checks, and optional `nuclei` template scanning. It turns one-off scans into
continuous monitoring with scheduling, change tracking, and alerts, surfaced through a CRT
"phosphor" terminal UI.

It's a small monorepo: a **Next.js** web app, a **FastAPI** backend with a **Celery** worker/beat,
and a shared, installable **`scanner_core`** Python package. Scans run as asynchronous Celery
tasks; results persist to PostgreSQL and render live in the dashboard.

> **Authorization first.** Every scan request must carry `i_own_this_target: true` — a legal
> acknowledgement that you own or are permitted to scan the target. Only scan assets you own.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Scanner modules](#scanner-modules-packagesscanner_core)
- [Tech stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Environment variables](#environment-variables)
- [Using the app](#using-the-app)
- [Running a scan via the API](#running-a-scan-via-the-api)
- [API reference](#api-reference)
- [Testing](#testing)
- [Database migrations](#database-migrations)
- [Project structure](#project-structure)
- [Concepts & glossary](#concepts--glossary)
- [Roadmap](#roadmap)
- [Key constraints](#key-constraints)
- [Disclaimer & license](#disclaimer--license)

---

## Features

**Discovery & recon**
- Port scanning & service/version fingerprinting (`nmap -sV`)
- DNS enumeration (A/AAAA/MX/TXT/NS/CNAME), subdomain brute-forcing, **zone-transfer (AXFR) detection**
- Subdomain discovery unified from brute-force **and** Certificate Transparency (crt.sh)
- WHOIS intelligence · Shodan integration · crt.sh certificate analysis

**Vulnerability detection**
- Version-aware **CVE matching** against the NVD v2 API, with CVSS scores and severity
- Web exposure checks: exposed `.git`/`.env`/backups, `server-status`, `phpinfo`, actuator,
  swagger; directory listing; **CORS misconfig**; missing cookie flags; clickjacking
- TLS audit: certificate validity/expiry, protocol version, and SANs
- **Subdomain takeover** detection (dangling CNAMEs + unclaimed S3 / GitHub Pages / Heroku / …)
- Email posture: **SPF & DMARC** grading (spoofability)
- **Nuclei** template scanning against discovered HTTP URLs (optional binary)
- Unified **Findings** model + 0–100 **risk score** & severity breakdown

**Monitoring & automation**
- Recurring/scheduled scans via a Celery **beat** dispatcher
- Scan-to-scan **diffing** — new/resolved CVEs, opened/closed ports, risk delta
- Change **alerts** on new high/critical findings or rising risk
- Out-of-band **notifications** (email/SMTP + webhook) with a configurable minimum severity
- Per-target risk-over-time history

**Platform**
- Google sign-in (NextAuth) with **per-user scan isolation**; the API is locked down behind a
  Backend-For-Frontend and is **fail-closed**
- CRT "phosphor" terminal dashboard (Next.js 16, React 19, Tailwind 4, Recharts)
- Async processing (Celery + Redis) · PostgreSQL persistence · Alembic migrations
- Cooperative scan **cancel** + a beat **reaper** that recovers scans a dead worker left hanging

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
   PostgreSQL ◀── scans/schedules/alerts/results ──┘   Redis (broker/result)
```

The browser talks only to the Next.js app, which authenticates the user (Google/NextAuth) and
proxies same-origin requests (`/api/easm/*`) to FastAPI as a **Backend-For-Frontend** — injecting
`X-Internal-Secret` + `X-User-Email`. `POST /api/scans` persists a `Scan` row and enqueues a
Celery task; the worker runs the pipeline, updating `status`/`current_module` live so the UI can
poll progress. **Beat** drives recurring scans (`enqueue_due_scans`) and stuck-scan recovery
(`reap_stuck_scans`); alert delivery runs out-of-band (`deliver_alert`).

### Scan pipeline (per `MODULE_ORDER`)

```text
port_scanner → cve_lookup → dns_enum → osint_fetcher → service_probe
            → web_audit → takeover_check → email_audit → nuclei_scan
                                   │
                                   ▼
                            report_gen  →  ScanReport
        (CVEs + Findings → severity summary + 0–100 risk score)
```

Each module degrades gracefully: a failure (or a missing optional dependency like a Shodan/NVD
key or the `nuclei` binary) is recorded **per-module** and the scan still completes with partial
results. All modules return Pydantic models from `packages/scanner_core/models.py`; the final
`ScanReport` is serialized to `Scan.result_json` and parsed back via `Scan.result`.

---

## Scanner modules (`packages/scanner_core/`)

| Module | Purpose |
|--------|---------|
| `port_scanner.py`  | Discover open ports + service/version (`nmap` via `python-nmap`). Feeds everything downstream. |
| `cve_lookup.py`    | Version-aware CVE matching via the NVD v2 API, with CVSS + severity. |
| `dns_enum.py`      | DNS records, subdomain brute-force, zone-transfer (AXFR) check. |
| `osint_fetcher.py` | WHOIS, Shodan, crt.sh certificates & cert-derived subdomains. |
| `service_probe.py` | HTTP fingerprint/headers, missing security headers, and TLS cert details. |
| `web_audit.py`     | Exposed files/paths, directory listing, CORS, cookie flags, clickjacking. |
| `takeover.py`      | Subdomain takeover (dangling CNAME / unclaimed third-party service). |
| `email_audit.py`   | SPF & DMARC grading. |
| `nuclei_scan.py`   | ProjectDiscovery Nuclei templates (optional binary). |
| `report_gen.py`    | Aggregate CVEs + Findings, severity summary, 0–100 risk score. |
| `models.py`        | Shared Pydantic models (incl. `PortResult`, `CVEResult`, `Finding`, `ScanReport`). |

---

## Tech stack

- **Frontend:** Next.js 16, React 19, TypeScript, Tailwind CSS 4, Radix UI, Recharts, NextAuth (Google)
- **Backend:** FastAPI, Uvicorn, SQLAlchemy 2, Alembic, Pydantic 2
- **Worker:** Celery 5 (+ beat), Redis broker/result backend
- **Data:** PostgreSQL 16, Redis 7
- **Recon/security:** `nmap`, optional `nuclei`, Shodan, WHOIS, crt.sh, `httpx`/`requests`, `dnspython`
- **Infra:** Docker / Docker Compose

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.11+ | Backend, worker, and `scanner_core`. |
| Node.js | 20+ | Frontend (`apps/web`). |
| Docker + Compose | recent | Runs PostgreSQL 16 + Redis 7. |
| **nmap** | recent | **Required** — `port_scanner` shells out to it; must be on `PATH`. |
| nuclei | recent | **Optional** — enables `nuclei_scan`. Single Go binary on `PATH`. |
| Google OAuth credentials | — | Required for web sign-in (client ID + secret). |

Install the external binaries:

```bash
# nmap (required)
#   macOS:    brew install nmap
#   Debian:   sudo apt-get install nmap
#   Windows:  https://nmap.org/download.html   (ensure nmap is on PATH)

# nuclei (optional)
#   Windows:  winget install ProjectDiscovery.Nuclei
#   else:     https://github.com/projectdiscovery/nuclei
```

---

## Quick start

### 1. Clone and start infrastructure

```bash
git clone https://github.com/thrid3v/External-Surface-Attack-Monitoring-Platform.git easm
cd easm
docker compose up -d        # PostgreSQL on :5432, Redis on :6379
```

### 2. Backend (`apps/api`)

```bash
cd apps/api
python -m venv venv
# Activate the venv:
#   macOS/Linux:  source venv/bin/activate
#   Windows:      venv\Scripts\Activate.ps1
pip install -r requirements.txt   # also installs scanner_core (editable) + test tooling

cp .env.example .env              # then edit values (see Environment variables)
alembic upgrade head              # create the schema (scans / schedules / alerts / notification_settings)
```

Run the three backend processes, each in its own terminal (venv active, from `apps/api`):

```bash
# Terminal A — API
uvicorn main:app --reload --port 8000
#   Docs: http://localhost:8000/docs   ·   Health: /health

# Terminal B — Celery worker
celery -A workers.scan_worker worker --loglevel=info          # macOS/Linux
celery -A workers.scan_worker worker --loglevel=info -P solo  # Windows (no fork support)

# Terminal C — Celery beat (recurring scans + stuck-scan reaper)
#   Run beat as its own process; the worker's embedded -B flag is unsupported on Windows.
celery -A workers.scan_worker beat --loglevel=info
```

### 3. Frontend (`apps/web`)

```bash
cd apps/web
npm install
cp .env.local.example .env.local   # then edit values (Google OAuth, secrets…)
npm run dev                        # http://localhost:3000
```

Open **http://localhost:3000**, sign in with Google, and start a scan.

> The `INTERNAL_API_SECRET` in `apps/web/.env.local` **must exactly match** the one in
> `apps/api/.env`, or the API will reject every request (it's fail-closed).

---

## Environment variables

Two example files are provided — copy each to its real name and fill it in. **Never commit real
secrets.** (`.env.example` at the repo root is a combined reference of both.)

### Backend — `apps/api/.env`

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `DATABASE_URL` | ✅ | — | PostgreSQL SQLAlchemy URL, e.g. `postgresql://user:password@localhost:5432/easm`. |
| `REDIS_URL` | ✅ | `redis://localhost:6379/0` | Celery broker + result backend. |
| `INTERNAL_API_SECRET` | ✅ | — | Shared secret with the web BFF. API is **fail-closed** without it; use a long random value. |
| `FRONTEND_URL` | — | `http://localhost:3000` | Comma-separated CORS origins; also used to build links in alert emails. |
| `SHODAN_API_KEY` | — | — | Enables Shodan OSINT enrichment (degrades gracefully if unset). |
| `NVD_API_KEY` | — | — | Raises the NVD rate limit (5→50 requests / 30s) for CVE lookups. |
| `SCAN_TIMEOUT` | — | `300` | Per-scan wall-clock budget, in seconds. |
| `SMTP_HOST` | — | — | Email-alert transport. **Blank disables email delivery** (webhooks still work). |
| `SMTP_PORT` | — | `587` | SMTP port. |
| `SMTP_USERNAME` | — | — | SMTP auth username. |
| `SMTP_PASSWORD` | — | — | SMTP auth password. |
| `SMTP_FROM` | — | `easm@localhost` | From address for alert emails. |
| `SMTP_STARTTLS` | — | `true` | Use STARTTLS for SMTP. |

### Frontend — `apps/web/.env.local`

| Variable | Required | Default | Description |
|----------|:--------:|---------|-------------|
| `API_URL` | ✅ | `http://127.0.0.1:8000` | Server-side FastAPI base URL (the BFF proxy target). |
| `INTERNAL_API_SECRET` | ✅ | — | Must **equal** the API's value. |
| `NEXTAUTH_URL` | ✅ | `http://localhost:3000` | NextAuth base URL. |
| `NEXTAUTH_SECRET` | ✅ | — | NextAuth JWT signing secret (long random value). |
| `GOOGLE_CLIENT_ID` | ✅ | — | Google OAuth client ID. |
| `GOOGLE_CLIENT_SECRET` | ✅ | — | Google OAuth client secret. |
| `NEXT_PUBLIC_API_URL` | — | — | Reserved. The client currently calls the same-origin BFF (`/api/easm`), so this is unused at runtime. |

> **Google OAuth setup** (Google Cloud Console → APIs & Services → Credentials → OAuth client ID,
> type *Web application*): add `http://localhost:3000` as an authorized origin and
> `http://localhost:3000/api/auth/callback/google` as a redirect URI, then paste the client
> ID/secret into `apps/web/.env.local`. If the consent screen is in *Testing*, add your Google
> account as a **Test user**.

---

## Using the app

1. Open **http://localhost:3000** and sign in with Google.
2. On the **Dashboard**, enter a target, pick a **port profile** (Common / Top 1000 / Full) and
   optionally toggle **modules**, confirm ownership, then scan. (`scanme.nmap.org` is Nmap's legal
   test host.)
3. The **report** shows the risk gauge, severity breakdown, a zone-transfer banner, the
   **Findings** tab (misconfig/exposure/TLS/takeover/email/nuclei), CVEs, ports, OSINT/DNS, HTTP,
   and a **"Changes since last scan"** diff once a target has ≥2 scans.
4. **Targets** lists every target with risk-over-time history; **Schedules** manages recurring
   scans; **Alerts** surfaces new risk from re-scans; **Settings → Notifications** configures
   email/webhook delivery and the minimum severity worth delivering.

---

## Running a scan via the API

In normal use the Next.js BFF injects the auth headers; direct calls must supply both
`X-Internal-Secret` and `X-User-Email`.

```bash
# Queue a scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -H "X-Internal-Secret: <your INTERNAL_API_SECRET>" \
  -H "X-User-Email: you@example.com" \
  -d '{ "target": "scanme.nmap.org", "profile": "top-1000", "i_own_this_target": true }'
# → { "scan_id": "...", "status": "pending", "message": "..." }

# Poll progress
curl http://localhost:8000/api/scans/<scan_id>/status \
  -H "X-Internal-Secret: <secret>" -H "X-User-Email: you@example.com"

# Fetch the full report once complete
curl http://localhost:8000/api/scans/<scan_id> \
  -H "X-Internal-Secret: <secret>" -H "X-User-Email: you@example.com"
```

**Port profiles** (or pass an explicit `port_range` like `"22,80,443"` / `"1-1000"`):

| Profile | Ports |
|---------|-------|
| `common` | 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8000,8080,8443 |
| `top-1000` *(default)* | `1-1000` |
| `full` | `1-65535` |

You can also restrict which modules run by passing a `modules` array (subset of `MODULE_ORDER`).

---

## API reference

All routes are under `/api`, require `X-Internal-Secret` + `X-User-Email`, and are scoped to the
acting user. Interactive docs: `http://localhost:8000/docs`.

### Scans — `/api/scans`
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scans` | Queue a scan (`target`, `profile`/`port_range`, `modules`, `i_own_this_target`). |
| `GET` | `/api/scans` | List the user's recent scans (latest 20). |
| `GET` | `/api/scans/{id}` | Full report (complete) / status (pending·running) / error (failed). |
| `GET` | `/api/scans/{id}/status` | Live status, `current_module`, and completed modules. |
| `GET` | `/api/scans/{id}/diff` | Diff vs. the previous completed scan of the same target. |
| `POST` | `/api/scans/{id}/cancel` | Cancel an in-flight scan (cooperative + best-effort revoke). |
| `DELETE` | `/api/scans/{id}` | Delete a scan. |

### Targets — `/api/targets`
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/targets` | Aggregated list of scanned targets. |
| `GET` | `/api/targets/{target}/history` | Scan history for a target. |
| `GET` | `/api/targets/{target}/latest` | Latest completed scan for a target. |

### Schedules — `/api/schedules`
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/schedules` | Create a recurring schedule. |
| `GET` | `/api/schedules` | List schedules. |
| `POST` | `/api/schedules/{id}/toggle` | Enable/disable a schedule. |
| `POST` | `/api/schedules/{id}/run` | Run a schedule immediately. |
| `DELETE` | `/api/schedules/{id}` | Delete a schedule. |

### Alerts — `/api/alerts`
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/alerts` | List alerts. |
| `POST` | `/api/alerts/{id}/read` | Mark one alert read. |
| `POST` | `/api/alerts/read-all` | Mark all alerts read. |

### Settings — `/api/settings`
| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/settings/notifications` | Get notification settings. |
| `PUT` | `/api/settings/notifications` | Update channels / min severity. |
| `POST` | `/api/settings/notifications/test` | Send a test email/webhook. |

Plus `GET /health` and `GET /` (service info).

---

## Testing

```bash
# scanner_core unit tests
pytest packages/scanner_core/tests/

# API tests (run from apps/api with the venv active)
cd apps/api
pytest tests/
```

Tests use SQLite and mocked HTTP (`respx` / `pytest-httpx`), so they don't need Postgres, Redis,
or network access.

Frontend lint:

```bash
cd apps/web
npm run lint
```

---

## Database migrations

Tables are auto-created on startup (`Base.metadata.create_all()`), but **Alembic** is the source
of truth for schema changes:

```bash
cd apps/api
alembic upgrade head                                  # apply migrations
alembic revision --autogenerate -m "describe change"  # create a new migration
```

> `apps/api/main.py` wraps `create_all()` in a try/except so the app can start without a DB
> (useful for running Alembic standalone). Don't remove that guard.

---

## Project structure

```text
easm/
├── apps/
│   ├── web/                        # Next.js 16 frontend
│   │   ├── app/(app)/              # dashboard, targets, schedules, alerts, settings, scan/[id]
│   │   ├── app/login/              # sign-in
│   │   ├── app/api/auth/…          # NextAuth route
│   │   ├── app/api/easm/[...path]/ # BFF proxy → FastAPI (injects auth headers)
│   │   ├── components/             # report panels, charts, app-shell, ui/
│   │   └── lib/                    # api.ts, server-api.ts, auth.ts, severity.ts, types.ts
│   ├── api/                        # FastAPI backend + Celery worker/beat
│   │   ├── main.py  auth.py  constants.py  deps.py  utils.py
│   │   ├── routers/                # scans, targets, schedules, alerts, settings
│   │   ├── services/               # diff (change detection), notifications (email/webhook)
│   │   ├── workers/scan_worker.py  # Celery app, run_scan pipeline, beat tasks, reaper, delivery
│   │   ├── db/models.py            # Scan, Schedule, Alert, NotificationSettings
│   │   └── alembic/                # migrations
│   └── mcp_server/                 # MCP server (placeholder / WIP)
├── packages/
│   └── scanner_core/               # shared, installable scanning package (+ tests)
└── docker-compose.yml              # PostgreSQL 16 + Redis 7
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

**TLS certificates** — enable HTTPS; their SANs often reveal more infrastructure. EASM records cert validity/expiry, protocol version, and SANs.

**WHOIS** — domain registration/ownership (registrar, org, dates, name servers, country).

**OSINT** — publicly available intel (WHOIS, Shodan, crt.sh, public DNS) gathered passively.

**Security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy; missing headers indicate weak posture.

</details>

---

## Roadmap

- MCP server (`apps/mcp_server/`) exposing scans/reports as tools — currently a placeholder
- Cloud exposure checks (open S3 buckets, unauthenticated Redis/Mongo/Elasticsearch)
- Secrets-in-JavaScript / leaked API-key scanning
- DKIM selector probing
- Censys integration & threat-intel enrichment
- PDF report export & multi-tenant org support

---

## Key constraints

- **Scan authorization:** the API requires `i_own_this_target: true` on every scan.
- **Fail-closed API:** requests without a valid `INTERNAL_API_SECRET` (+ `X-User-Email`) are rejected.
- **nmap is required**; **nuclei is optional** (auto-detected on `PATH`).
- **Windows + Celery:** use the `-P solo` worker pool and run **beat as a separate process**
  (the embedded `-B` flag is unsupported on Windows). See `CLAUDE.md` and `apps/web/AGENTS.md`
  for additional contributor notes.

---

## Disclaimer & license

For educational, research, and **authorized** security assessment only. Only scan systems you
have explicit permission to test — unauthorized scanning may violate laws, regulations, or
policies. The `i_own_this_target` acknowledgement is required on every scan; use this tool
responsibly.

Licensed under the **MIT License**.
