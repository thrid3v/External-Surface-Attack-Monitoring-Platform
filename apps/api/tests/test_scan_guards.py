"""Tests for scan-creation SSRF target validation, rate limiting, and the
matching ownership/validation guards on recurring schedules."""

from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth import get_current_user
from db.models import Scan
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


# --- scan creation: SSRF target policy --------------------------------------

def test_create_scan_blocks_private_target(db, monkeypatch):
    import routers.scans as scans_mod

    monkeypatch.setattr(scans_mod.run_scan, "apply_async", lambda *a, **k: None)
    res = _client(db, scans_mod.router, "/api/scans").post(
        "/api/scans", json={"target": "169.254.169.254", "i_own_this_target": True}
    )
    assert res.status_code == 422


def test_create_scan_allows_public_target(db, monkeypatch):
    import routers.scans as scans_mod

    monkeypatch.setattr(scans_mod.run_scan, "apply_async", lambda *a, **k: None)
    res = _client(db, scans_mod.router, "/api/scans").post(
        "/api/scans", json={"target": "93.184.216.34", "i_own_this_target": True}
    )
    assert res.status_code == 200


def test_create_scan_requires_ownership(db):
    import routers.scans as scans_mod

    res = _client(db, scans_mod.router, "/api/scans").post(
        "/api/scans", json={"target": "93.184.216.34", "i_own_this_target": False}
    )
    assert res.status_code == 403


# --- scan creation: rate limiting -------------------------------------------

def test_create_scan_rejects_when_too_many_active(db, monkeypatch):
    import routers.scans as scans_mod
    from services import rate_limit

    monkeypatch.setattr(scans_mod.run_scan, "apply_async", lambda *a, **k: None)
    monkeypatch.setattr(rate_limit, "max_concurrent_scans", lambda: 2)

    for i in range(2):
        db.add(Scan(id=f"act{i}", owner_email=USER, target="x.com", status="running", created_at=_now()))
    db.commit()

    res = _client(db, scans_mod.router, "/api/scans").post(
        "/api/scans", json={"target": "93.184.216.34", "i_own_this_target": True}
    )
    assert res.status_code == 429


def test_create_scan_active_limit_is_per_user(db, monkeypatch):
    """Another user's running scans don't count against this user's limit."""
    import routers.scans as scans_mod
    from services import rate_limit

    monkeypatch.setattr(scans_mod.run_scan, "apply_async", lambda *a, **k: None)
    monkeypatch.setattr(rate_limit, "max_concurrent_scans", lambda: 1)

    db.add(Scan(id="other", owner_email="someone@else.com", target="x.com", status="running", created_at=_now()))
    db.commit()

    res = _client(db, scans_mod.router, "/api/scans").post(
        "/api/scans", json={"target": "93.184.216.34", "i_own_this_target": True}
    )
    assert res.status_code == 200


# --- schedules: ownership + SSRF parity with one-off scans ------------------

def test_create_schedule_requires_ownership(db):
    import routers.schedules as sched_mod

    res = _client(db, sched_mod.router, "/api/schedules").post(
        "/api/schedules", json={"target": "93.184.216.34", "interval_minutes": 1440}
    )
    assert res.status_code == 403


def test_create_schedule_blocks_private_target(db):
    import routers.schedules as sched_mod

    res = _client(db, sched_mod.router, "/api/schedules").post(
        "/api/schedules",
        json={"target": "10.0.0.5", "interval_minutes": 1440, "i_own_this_target": True},
    )
    assert res.status_code == 422


def test_create_schedule_allows_public_target(db):
    import routers.schedules as sched_mod

    res = _client(db, sched_mod.router, "/api/schedules").post(
        "/api/schedules",
        json={"target": "93.184.216.34", "interval_minutes": 1440, "i_own_this_target": True},
    )
    assert res.status_code == 200
