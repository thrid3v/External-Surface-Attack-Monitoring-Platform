"""Tests for the cancel and run-now lifecycle endpoints."""

import uuid
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth import get_current_user
from db.models import Scan, Schedule
from deps import get_db

USER = "u@example.com"


def _client(db, router, prefix):
    app = FastAPI()
    app.include_router(router, prefix=prefix)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: USER
    return TestClient(app)


def _now():
    return datetime.now(timezone.utc)


# --- cancel ------------------------------------------------------------------

def test_cancel_running_scan_flips_to_canceled(db, monkeypatch):
    import routers.scans as scans_mod

    class _FakeResult:
        def revoke(self, terminate=False):
            pass

    monkeypatch.setattr(scans_mod.run_scan, "AsyncResult", lambda task_id: _FakeResult())

    scan = Scan(id="s1", owner_email=USER, target="x.com", status="running", created_at=_now())
    db.add(scan)
    db.commit()

    res = _client(db, scans_mod.router, "/api/scans").post("/api/scans/s1/cancel")
    assert res.status_code == 200
    db.refresh(scan)
    assert scan.status == "canceled"
    assert scan.completed_at is not None


def test_cancel_completed_scan_is_conflict(db):
    import routers.scans as scans_mod

    scan = Scan(id="s2", owner_email=USER, target="x.com", status="complete", created_at=_now())
    db.add(scan)
    db.commit()

    res = _client(db, scans_mod.router, "/api/scans").post("/api/scans/s2/cancel")
    assert res.status_code == 409


def test_cancel_other_users_scan_is_404(db):
    import routers.scans as scans_mod

    scan = Scan(id="s3", owner_email="someone@else.com", target="x.com", status="running", created_at=_now())
    db.add(scan)
    db.commit()

    res = _client(db, scans_mod.router, "/api/scans").post("/api/scans/s3/cancel")
    assert res.status_code == 404


# --- run now -----------------------------------------------------------------

def test_run_schedule_now_creates_scan_and_advances(db, monkeypatch):
    import routers.schedules as sched_mod

    captured = {}
    monkeypatch.setattr(
        sched_mod.run_scan,
        "apply_async",
        lambda args, task_id: captured.update(args=args, task_id=task_id),
    )

    schedule = Schedule(
        id="sch1", owner_email=USER, target="acme.com", port_range="1-1000",
        interval_minutes=1440, enabled=True, created_at=_now(),
    )
    db.add(schedule)
    db.commit()

    res = _client(db, sched_mod.router, "/api/schedules").post("/api/schedules/sch1/run")
    assert res.status_code == 200
    scan_id = res.json()["scan_id"]

    assert db.query(Scan).filter(Scan.id == scan_id).first() is not None
    assert captured["task_id"] == scan_id
    db.refresh(schedule)
    assert schedule.last_run_at is not None
    assert schedule.next_run_at is not None
