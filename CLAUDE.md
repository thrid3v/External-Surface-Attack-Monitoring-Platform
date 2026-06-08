# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EASM (External Attack Surface Management) — a platform for discovering and assessing an organization's external attack surface. Scans run as async Celery tasks through a modular pipeline: port scanning → CVE lookup → DNS enumeration → OSINT → HTTP/TLS probing → risk scoring.

## Repository Structure

```
easm/
├── apps/
│   ├── web/            # Next.js 15 frontend (React 19, TypeScript, Tailwind 4)
│   ├── api/            # FastAPI backend (Python)
│   └── mcp_server/     # MCP Server (placeholder)
├── packages/
│   └── scanner_core/   # Shared Python scanning modules (installable package)
└── docker-compose.yml  # PostgreSQL 16 + Redis 7
```

## Development Commands

### Infrastructure
```bash
docker compose up -d    # Start PostgreSQL (5432) and Redis (6379)
```

### Frontend (`apps/web/`)
```bash
npm run dev             # Dev server at localhost:3000
npm run build
npm run lint
```

### Backend (`apps/api/`)
```bash
# One-time setup
python -m venv venv
pip install -r requirements.txt

# Run API
uvicorn main:app --reload --port 8000

# Run Celery worker (Windows requires -P solo)
celery -A workers.scan_worker worker --loglevel=info -P solo
# Linux/macOS:
celery -A workers.scan_worker worker --loglevel=info
```

### Tests (`packages/scanner_core/`)
```bash
pytest packages/scanner_core/tests/
```

### Database Migrations (`apps/api/`)
```bash
alembic upgrade head
alembic revision --autogenerate -m "description"
```

## Environment Setup

Copy `.env.example` to `apps/api/.env`:
```
DATABASE_URL=postgresql://user:password@localhost:5432/easm
REDIS_URL=redis://localhost:6379/0
SHODAN_API_KEY=        # Optional — OSINT fetcher degrades gracefully
NVD_API_KEY=           # Optional — CVE lookup degrades gracefully
FRONTEND_URL=http://localhost:3000
SCAN_TIMEOUT=300
```

Frontend uses `NEXT_PUBLIC_API_URL` (defaults to same origin if unset).

## Architecture

### Scan Pipeline

Scans are triggered via `POST /api/scans`, which persists a `Scan` record and enqueues a Celery task. The worker in `apps/api/workers/scan_worker.py` runs modules sequentially per `MODULE_ORDER` in `apps/api/constants.py`:

```python
MODULE_ORDER = ["port_scanner", "cve_lookup", "dns_enum", "osint_fetcher", "service_probe"]
```

Each module is imported from `packages/scanner_core/` and returns Pydantic models defined in `packages/scanner_core/models.py`. Results are serialized to `result_json` (Text column) on the `Scan` DB record. `current_module` and `status` are updated live so the frontend can poll progress.

### Frontend Data Flow

- `apps/web/lib/api.ts` — all API calls (`startScan`, `getRecentScans`, `getScanStatus`, `getScanReport`)
- `apps/web/app/page.tsx` — homepage with scan initiation and recent scans list
- `apps/web/app/scan/[id]/page.tsx` — polls `getScanStatus` until complete, then renders report panels
- Report panels (`port_table`, `CVE_list`, `HTTP_panel`, `OSINT_panel`, `risk_score`) each receive their slice of `ScanReport`

### Backend API

- `apps/api/main.py` — FastAPI app, CORS setup, router registration
- `apps/api/routers/scans.py` — scan CRUD + status endpoint
- `apps/api/db/models.py` — SQLAlchemy `Scan` model; `.result` property auto-parses `result_json`
- `apps/api/deps.py` — DB session dependency injection
- Database is auto-created on startup via `Base.metadata.create_all()` if `DATABASE_URL` is set; Alembic handles schema migrations

### Scanner Core Package

`packages/scanner_core/` is an installable Python package (listed in `apps/api/requirements.txt` as a path dependency). Modules: `port_scanner`, `cve_lookup`, `dns_enum`, `osint_fetcher`, `service_probe`, `report_gen`. All public return types are Pydantic models from `scanner_core.models`.

## Key Constraints

- **Scan authorization**: The API requires `i_own_this_target: true` in the scan request body — this is a legal acknowledgment that the requester owns the target.
- **Windows Celery**: Must use `-P solo` pool on Windows (no fork support).
- **Next.js version note**: `apps/web/AGENTS.md` documents breaking changes between Next.js versions — read it before modifying the frontend routing or data-fetching patterns.
- **DB initialization**: `apps/api/main.py` wraps `create_all()` in a try/except so the app starts without a DB (useful for running Alembic standalone). Don't remove that guard.
