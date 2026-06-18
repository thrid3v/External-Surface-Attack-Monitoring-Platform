"""
rate_limit.py
-------------
Per-user scan rate limiting.

Scans are expensive (they shell out to nmap/nuclei and make outbound network
requests), so a single user must not be able to exhaust the worker pool or run
up cost. Two limits are enforced at scan-creation time:

* ``MAX_CONCURRENT_SCANS_PER_USER`` — how many of a user's scans may be
  ``pending``/``running`` at once.
* ``MAX_SCANS_PER_HOUR`` — a rolling one-hour cap per user.

Both are environment-configurable. Limits are advisory (enforced in the API
layer, not the DB) which is sufficient for abuse/cost control; system-initiated
scans from the beat dispatcher intentionally bypass them.
"""

import os
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from db.models import Scan

ACTIVE_STATUSES = ("pending", "running")


def max_concurrent_scans() -> int:
    return int(os.getenv("MAX_CONCURRENT_SCANS_PER_USER", "3"))


def max_scans_per_hour() -> int:
    return int(os.getenv("MAX_SCANS_PER_HOUR", "50"))


def enforce_scan_rate_limit(db: Session, user: str) -> None:
    """Raise HTTP 429 if *user* has hit a concurrency or hourly scan limit."""
    active = (
        db.query(Scan)
        .filter(Scan.owner_email == user, Scan.status.in_(ACTIVE_STATUSES))
        .count()
    )
    if active >= max_concurrent_scans():
        raise HTTPException(
            status_code=429,
            detail=(
                f"Too many concurrent scans (limit {max_concurrent_scans()}). "
                "Wait for a running scan to finish."
            ),
        )

    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    recent = (
        db.query(Scan)
        .filter(Scan.owner_email == user, Scan.created_at >= cutoff)
        .count()
    )
    if recent >= max_scans_per_hour():
        raise HTTPException(
            status_code=429,
            detail=f"Scan rate limit reached ({max_scans_per_hour()}/hour). Try again later.",
        )
