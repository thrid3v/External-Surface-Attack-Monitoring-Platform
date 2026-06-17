"""Tests for the per-user notification settings API."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth import get_current_user
from deps import get_db
from services import notifications


def make_client(db):
    from routers.settings import router as settings_router

    app = FastAPI()
    app.include_router(settings_router, prefix="/api/settings")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: "u@example.com"
    return TestClient(app)


def test_get_creates_default_settings(db):
    client = make_client(db)
    res = client.get("/api/settings/notifications")
    assert res.status_code == 200
    body = res.json()
    assert body["owner_email"] == "u@example.com"
    assert body["email_enabled"] is False
    assert body["webhook_enabled"] is False
    assert body["min_severity"] == "warning"


def test_put_upserts_settings(db):
    client = make_client(db)
    res = client.put(
        "/api/settings/notifications",
        json={
            "email_enabled": True,
            "email_address": "alerts@acme.com",
            "webhook_enabled": True,
            "webhook_url": "https://hook.example/x",
            "min_severity": "high",
        },
    )
    assert res.status_code == 200
    assert res.json()["email_address"] == "alerts@acme.com"

    # Persisted: a follow-up GET reflects the update (no duplicate row).
    again = client.get("/api/settings/notifications").json()
    assert again["webhook_url"] == "https://hook.example/x"
    assert again["min_severity"] == "high"


def test_put_rejects_unknown_severity(db):
    client = make_client(db)
    res = client.put("/api/settings/notifications", json={"min_severity": "bogus"})
    assert res.status_code == 422


def test_test_endpoint_reports_success(db, monkeypatch):
    client = make_client(db)
    client.put(
        "/api/settings/notifications",
        json={"webhook_enabled": True, "webhook_url": "https://hook.example/x"},
    )
    monkeypatch.setattr(notifications, "send_webhook", lambda s, a: None)
    res = client.post("/api/settings/notifications/test")
    assert res.status_code == 200
    assert res.json()["webhook"]["ok"] is True


def test_test_endpoint_reports_failure(db, monkeypatch):
    client = make_client(db)
    client.put(
        "/api/settings/notifications",
        json={"webhook_enabled": True, "webhook_url": "https://hook.example/x"},
    )

    def boom(s, a):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(notifications, "send_webhook", boom)
    res = client.post("/api/settings/notifications/test")
    assert res.status_code == 200
    body = res.json()
    assert body["webhook"]["ok"] is False
    assert "connection refused" in body["webhook"]["error"]
