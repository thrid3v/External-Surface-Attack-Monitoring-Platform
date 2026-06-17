"""Tests for the per-user alert delivery service."""

import uuid
from datetime import datetime, timezone

import pytest

from db.models import Alert, NotificationSettings
from services import notifications


def _make_alert(severity: str, owner: str = "u@example.com") -> Alert:
    return Alert(
        id=str(uuid.uuid4()),
        owner_email=owner,
        target="acme.com",
        scan_id="scan-1",
        type="new_cve",
        severity=severity,
        message="2 new critical findings on acme.com",
        read=False,
        created_at=datetime.now(timezone.utc),
    )


def _settings(db, **kwargs) -> NotificationSettings:
    defaults = dict(
        id=str(uuid.uuid4()),
        owner_email="u@example.com",
        email_enabled=False,
        email_address=None,
        webhook_enabled=False,
        webhook_url=None,
        min_severity="warning",
    )
    defaults.update(kwargs)
    s = NotificationSettings(**defaults)
    db.add(s)
    db.commit()
    return s


def _capture(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(notifications, "send_email", lambda s, a: calls.append("email"))
    monkeypatch.setattr(notifications, "send_webhook", lambda s, a: calls.append("webhook"))
    return calls


# --- severity ordering -------------------------------------------------------

def test_severity_rank_orders_info_to_critical():
    assert notifications.severity_rank("info") < notifications.severity_rank("warning")
    assert notifications.severity_rank("warning") < notifications.severity_rank("high")
    assert notifications.severity_rank("high") < notifications.severity_rank("critical")


def test_unknown_severity_ranks_lowest():
    assert notifications.severity_rank("bogus") == notifications.severity_rank("info")


def test_severity_rank_is_case_insensitive():
    assert notifications.severity_rank("CRITICAL") == notifications.severity_rank("critical")


# --- delivery orchestration --------------------------------------------------

def test_deliver_skips_when_no_settings(db, monkeypatch):
    calls = _capture(monkeypatch)
    notifications.deliver_alert(db, _make_alert("critical"))
    assert calls == []


def test_deliver_below_threshold_is_suppressed(db, monkeypatch):
    _settings(db, email_enabled=True, webhook_enabled=True, webhook_url="https://hook", min_severity="high")
    calls = _capture(monkeypatch)
    notifications.deliver_alert(db, _make_alert("warning"))  # warning < high
    assert calls == []


def test_deliver_at_threshold_is_sent(db, monkeypatch):
    _settings(db, email_enabled=True, min_severity="high")
    calls = _capture(monkeypatch)
    notifications.deliver_alert(db, _make_alert("high"))
    assert calls == ["email"]


def test_deliver_fans_out_to_all_enabled_channels(db, monkeypatch):
    _settings(db, email_enabled=True, webhook_enabled=True, webhook_url="https://hook", min_severity="warning")
    calls = _capture(monkeypatch)
    notifications.deliver_alert(db, _make_alert("critical"))
    assert sorted(calls) == ["email", "webhook"]


def test_deliver_only_to_enabled_channel(db, monkeypatch):
    _settings(db, email_enabled=False, webhook_enabled=True, webhook_url="https://hook", min_severity="warning")
    calls = _capture(monkeypatch)
    notifications.deliver_alert(db, _make_alert("critical"))
    assert calls == ["webhook"]


def test_deliver_webhook_enabled_without_url_is_skipped(db, monkeypatch):
    _settings(db, webhook_enabled=True, webhook_url=None, min_severity="warning")
    calls = _capture(monkeypatch)
    notifications.deliver_alert(db, _make_alert("critical"))
    assert "webhook" not in calls


# --- channel adapters --------------------------------------------------------

def test_send_webhook_posts_expected_payload(monkeypatch):
    captured: dict = {}

    class _Resp:
        def raise_for_status(self):
            captured["raised"] = True

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(notifications.httpx, "post", fake_post)
    monkeypatch.setattr(notifications, "_resolve_ips", lambda host: ["93.184.216.34"])
    monkeypatch.setenv("FRONTEND_URL", "https://easm.example")

    settings = NotificationSettings(
        id="s", owner_email="u@example.com", webhook_enabled=True,
        webhook_url="https://hook.example/x", min_severity="warning",
    )
    alert = _make_alert("critical")
    notifications.send_webhook(settings, alert)

    assert captured["url"] == "https://hook.example/x"
    assert captured["json"]["target"] == "acme.com"
    assert captured["json"]["severity"] == "critical"
    assert captured["json"]["url"] == "https://easm.example/scan/scan-1"
    assert captured["raised"] is True


def test_send_webhook_blocks_cloud_metadata_address(monkeypatch):
    posted = []
    monkeypatch.setattr(notifications.httpx, "post", lambda *a, **k: posted.append(a))
    s = NotificationSettings(
        id="s", owner_email="u@example.com", webhook_enabled=True,
        webhook_url="http://169.254.169.254/latest/meta-data/", min_severity="warning",
    )
    with pytest.raises(notifications.WebhookURLNotAllowed):
        notifications.send_webhook(s, _make_alert("critical"))
    assert posted == []  # never POSTed to the internal address


def test_send_webhook_blocks_loopback(monkeypatch):
    monkeypatch.setattr(notifications, "_resolve_ips", lambda host: ["127.0.0.1"])
    posted = []
    monkeypatch.setattr(notifications.httpx, "post", lambda *a, **k: posted.append(a))
    s = NotificationSettings(
        id="s", owner_email="u@example.com", webhook_enabled=True,
        webhook_url="http://internal.local/hook", min_severity="warning",
    )
    with pytest.raises(notifications.WebhookURLNotAllowed):
        notifications.send_webhook(s, _make_alert("critical"))
    assert posted == []


def test_send_webhook_allows_public_target(monkeypatch):
    monkeypatch.setattr(notifications, "_resolve_ips", lambda host: ["93.184.216.34"])

    class _Resp:
        def raise_for_status(self):
            pass

    posted = []
    monkeypatch.setattr(notifications.httpx, "post", lambda url, json, timeout: (posted.append(url), _Resp())[1])
    s = NotificationSettings(
        id="s", owner_email="u@example.com", webhook_enabled=True,
        webhook_url="https://hooks.example.com/x", min_severity="warning",
    )
    notifications.send_webhook(s, _make_alert("critical"))  # must not raise
    assert posted == ["https://hooks.example.com/x"]


def test_send_email_skips_when_smtp_unconfigured(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    called = {"smtp": False}
    monkeypatch.setattr(notifications.smtplib, "SMTP", lambda *a, **k: called.__setitem__("smtp", True))

    settings = NotificationSettings(
        id="s", owner_email="u@example.com", email_enabled=True, min_severity="warning",
    )
    notifications.send_email(settings, _make_alert("critical"))
    assert called["smtp"] is False


def test_deliver_isolates_a_failing_channel(db, monkeypatch):
    _settings(db, email_enabled=True, webhook_enabled=True, webhook_url="https://hook", min_severity="warning")
    calls: list[str] = []

    def boom(s, a):
        raise RuntimeError("smtp down")

    monkeypatch.setattr(notifications, "send_email", boom)
    monkeypatch.setattr(notifications, "send_webhook", lambda s, a: calls.append("webhook"))
    # One channel failing must not raise, and must not prevent the other.
    notifications.deliver_alert(db, _make_alert("critical"))
    assert calls == ["webhook"]
