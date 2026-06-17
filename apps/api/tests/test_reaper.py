"""Tests for the stuck-scan reaper."""

import uuid
from datetime import datetime, timedelta, timezone

from db.models import Scan
from workers.scan_worker import _reap_stuck_scans


def _scan(db, status, started_delta=None, created_delta=timedelta(0)):
    now = datetime.now(timezone.utc)
    scan = Scan(
        id=str(uuid.uuid4()),
        target="x.com",
        status=status,
        started_at=(now - started_delta) if started_delta else None,
        created_at=now - created_delta,
    )
    db.add(scan)
    db.commit()
    return scan


def test_reaps_running_scan_past_timeout(db):
    scan = _scan(db, "running", started_delta=timedelta(seconds=10_000))
    reaped = _reap_stuck_scans(db, timeout_seconds=300)
    db.refresh(scan)
    assert reaped == 1
    assert scan.status == "failed"
    assert scan.error_message
    assert scan.completed_at is not None


def test_does_not_reap_fresh_running_scan(db):
    scan = _scan(db, "running", started_delta=timedelta(seconds=10))
    reaped = _reap_stuck_scans(db, timeout_seconds=300)
    db.refresh(scan)
    assert reaped == 0
    assert scan.status == "running"


def test_reaps_old_pending_scan_by_created_at(db):
    scan = _scan(db, "pending", created_delta=timedelta(seconds=10_000))
    _reap_stuck_scans(db, timeout_seconds=300)
    db.refresh(scan)
    assert scan.status == "failed"


def test_ignores_completed_scans(db):
    scan = _scan(db, "complete", started_delta=timedelta(seconds=10_000))
    _reap_stuck_scans(db, timeout_seconds=300)
    db.refresh(scan)
    assert scan.status == "complete"
