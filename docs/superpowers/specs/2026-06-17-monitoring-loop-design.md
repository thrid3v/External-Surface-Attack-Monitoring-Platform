# EASM Monitoring Loop — Design

**Date:** 2026-06-17
**Status:** Approved (execute)
**Branch:** easm-improvements

## Goal

Close the three Tier-1 usability gaps that prevent EASM from delivering on its
core promise ("tell me when my external attack surface changes"):

1. **Alert delivery** — change-detection alerts currently live only in the DB +
   in-app bell. Add out-of-band delivery (email + webhook), configured per user.
2. **Activate scheduling** — `enqueue_due_scans` is configured but no `beat`
   process runs, so recurring scans never fire.
3. **Scan lifecycle** — recover stuck scans, allow manual "run now" / re-scan,
   and allow cancelling an in-flight scan.

No new Python dependencies are required: `httpx` (already present) for webhooks,
stdlib `smtplib` for email.

---

## Feature 1 — Per-user alert delivery

### Data model

New table `notification_settings`, one row per user (`owner_email` unique):

| column | type | notes |
|---|---|---|
| `id` | String(36) PK | uuid |
| `owner_email` | String(320), unique, indexed | identity |
| `email_enabled` | Boolean, default False | |
| `email_address` | String(320), nullable | defaults to `owner_email` when null |
| `webhook_enabled` | Boolean, default False | |
| `webhook_url` | String(1024), nullable | |
| `min_severity` | String(20), default `"warning"` | delivery threshold |
| `created_at` / `updated_at` | DateTime(tz) | |

Alembic migration adds the table. No other schema changes.

### Severity threshold

Ordering used everywhere: `info(0) < warning(1) < high(2) < critical(3)`.
An alert is delivered only when `severity_rank(alert) >= severity_rank(min_severity)`.
Default `warning` delivers `risk_increase` (warning) and high/critical CVE alerts,
suppresses bare `info`.

### Delivery service — `apps/api/services/notifications.py`

- `severity_rank(name) -> int` — single source of truth for ordering.
- `deliver_alert(db, alert) -> None` — loads the user's settings; returns early
  if no settings, no channel enabled, or below threshold; otherwise fans out to
  each enabled channel. Every channel send is wrapped so one failure never
  raises into the caller.
- `send_email(settings, alert)` — stdlib `smtplib`. SMTP transport from env:
  `SMTP_HOST`, `SMTP_PORT` (default 587), `SMTP_USERNAME`, `SMTP_PASSWORD`,
  `SMTP_FROM`, `SMTP_STARTTLS` (default true). Recipient = `email_address or owner_email`.
  If `SMTP_HOST` is unset, email is skipped (logged), never errors.
- `send_webhook(settings, alert)` — `httpx.post(webhook_url, json=payload, timeout=10)`.
  Payload: `{target, severity, type, message, scan_id, created_at, url}` where
  `url` is the frontend scan link (`FRONTEND_URL/scan/{scan_id}`).

### Delivery trigger — decoupled Celery task

New task `deliver_alert(alert_id)` in `scan_worker.py`. After
`_create_change_alerts` commits new alerts, it calls `deliver_alert.delay(alert.id)`
for each. The task re-loads the alert + settings and calls the service. This keeps
slow SMTP/webhook I/O off the scan task's critical path and gives independent retry.

### Settings API — `apps/api/routers/settings.py` (prefix `/api/settings`)

- `GET /notifications` — returns the user's settings, creating a default row on
  first access.
- `PUT /notifications` — upsert (validates `min_severity` and webhook URL shape).
- `POST /notifications/test` — synthesises a sample alert and runs delivery
  immediately, returning per-channel success/failure so users can verify config.

Registered in `main.py` alongside the other routers.

---

## Feature 2 — Activate scheduling

Run Celery **beat** as a separate process: `celery -A workers.scan_worker beat`.

> **Verified correction:** the original plan was to embed beat via the worker's
> `-B` flag, but `-B` is **rejected on Windows** ("`-B` option does not work on
> Windows. Please run celery beat as a separate service."). On Windows beat must
> be its own process; `-B` embedding is a Linux/macOS-only convenience. Docs and
> the live stack run beat standalone. (No code change — `beat_schedule` is defined
> on the Celery app and works either way.)

`enqueue_due_scans` (already implemented) then dispatches due schedules every 5 min,
alongside `reap_stuck_scans`.

---

## Feature 3 — Scan lifecycle

### Stuck-scan reaper

New task `reap_stuck_scans()` added to `beat_schedule` (every 300s). Marks any scan
in `pending`/`running` whose age exceeds `SCAN_TIMEOUT + 120s` as `failed` with
`error_message = "Reaped: exceeded time limit (worker may have stopped)"`. Age is
measured from `started_at` for running scans, `created_at` for pending scans.

### Run now / re-scan

- `POST /api/schedules/{id}/run` — creates a `Scan` from the schedule's stored
  `target`/`port_range`/`modules`, enqueues `run_scan`, advances `last_run_at` and
  `next_run_at`. Returns `{scan_id}`.
- Target "Re-scan now": frontend button posts to the existing
  `POST /api/scans` with the target prefilled and default profile/modules
  (one click, no prompt). No new endpoint needed.

### Cancel a running scan (cooperative)

- New scan status value `canceled` (string only — no migration).
- `POST /api/scans/{id}/cancel` — owner-scoped; if status is `pending`/`running`,
  set `status="canceled"`, `completed_at=now`, best-effort
  `run_scan.AsyncResult(task_id).revoke(terminate=True)`. (Celery task id is
  stored on the scan row — add a nullable `task_id` column via the same migration,
  or reuse `scan.id` as the task id by passing `task_id=scan_id` when enqueuing.)
  **Decision:** pass `task_id=scan_id` to `run_scan.apply_async` so no new column is
  needed and revoke targets a deterministic id.
- Worker: add `_check_canceled(db, scan)` called at each module boundary (next to
  `_maybe_fail_on_timeout`). It re-queries the scan's status; if `canceled`, the
  task stops gracefully (no result written, returns `{"status": "canceled"}`).
  On the solo pool this stops at the next module boundary; `revoke(terminate=True)`
  additionally prevents a still-queued task from starting.

---

## Frontend (`apps/web`)

Per `apps/web/AGENTS.md`, read the bundled Next docs under
`node_modules/next/dist/docs/` before writing any frontend code.

- **Settings page** `app/(app)/settings/page.tsx` + nav entry in `app-shell.tsx`:
  email toggle/address, webhook toggle/URL, min-severity select, Save, and a
  "Send test" button hitting `/settings/notifications/test`.
- **Cancel button** on `app/(app)/scan/[id]/page.tsx` when status is `pending`/`running`.
- **Run-now** button on schedules page; **Re-scan** button on target page.
- API client additions in `lib/api.ts` (client/BFF) and `lib/server-api.ts` (server),
  plus `lib/types.ts` for `NotificationSettings`.

All client calls flow through the existing BFF proxy (`app/api/easm/[...path]/route.ts`).

---

## Testing

- `services/notifications.py`: unit tests for `severity_rank` ordering, threshold
  gating, channel fan-out, and best-effort failure isolation (mock smtplib/httpx).
- `reap_stuck_scans`: test that aged pending/running scans flip to failed and fresh
  ones are untouched (in-memory/sqlite session or mocked query).
- Settings router: GET creates default; PUT upserts + validates; test endpoint
  reports per-channel result.
- Schedules `run`: creates a scan + advances schedule timestamps.
- Reuse existing pytest setup under `packages/scanner_core/tests/`; add API-side
  tests under `apps/api/tests/` (new) with a conftest providing a test DB session.

---

## Out of scope (deferred)

- Verified target ownership (DNS TXT challenge).
- Rate limiting / scan quotas.
- PDF export (separate button already stubbed).
- SMS / other channels.

---

## Implementation phases

1. **Backend — notifications**: model + migration, `services/notifications.py`,
   `deliver_alert` task wired into `_create_change_alerts`, `routers/settings.py`,
   register in `main.py`. Tests.
2. **Backend — scheduling + lifecycle**: beat `-B` + reaper task; schedule `run`
   endpoint; cancel endpoint + cooperative `_check_canceled` in worker;
   `apply_async(task_id=scan_id)`. Tests.
3. **Frontend**: settings page + nav, cancel/run-now/re-scan buttons, api client +
   types. (Read Next docs first.)
4. **Docs**: update `.env.example`, README, `CLAUDE.md` (worker `-B`, SMTP/webhook env).
