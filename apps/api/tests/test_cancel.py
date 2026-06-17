"""Tests for cooperative scan cancellation in the worker."""

import uuid
from datetime import datetime, timezone

from db.models import Scan
from workers.scan_worker import _check_canceled


def _scan(db, status):
    scan = Scan(
        id=str(uuid.uuid4()),
        target="x.com",
        status=status,
        created_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    return scan


def test_check_canceled_true_and_finalizes_when_canceled(db):
    scan = _scan(db, "canceled")
    assert _check_canceled(db, scan) is True
    db.refresh(scan)
    assert scan.completed_at is not None
    assert scan.current_module is None


def test_check_canceled_false_for_running(db):
    scan = _scan(db, "running")
    assert _check_canceled(db, scan) is False
