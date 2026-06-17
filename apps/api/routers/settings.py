"""
settings.py
-----------
Per-user notification settings: which out-of-band channels receive
change-detection alerts, where, and the minimum severity worth delivering.

SMTP transport credentials are server-side (environment); this router only
manages the per-user routing row and offers a ``/test`` action so a user can
verify their configuration end-to-end.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from auth import get_current_user
from db.models import Alert, NotificationSettings
from deps import get_db
from services import notifications

router = APIRouter()

VALID_SEVERITIES = ("info", "warning", "high", "critical")


class NotificationSettingsUpdate(BaseModel):
    email_enabled: bool | None = None
    email_address: str | None = None
    webhook_enabled: bool | None = None
    webhook_url: str | None = None
    min_severity: str | None = None

    @field_validator("min_severity")
    @classmethod
    def _validate_min_severity(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip().lower()
        if normalized not in VALID_SEVERITIES:
            raise ValueError(f"min_severity must be one of {', '.join(VALID_SEVERITIES)}")
        return normalized


def _serialize(s: NotificationSettings) -> dict[str, Any]:
    return {
        "owner_email": s.owner_email,
        "email_enabled": s.email_enabled,
        "email_address": s.email_address,
        "webhook_enabled": s.webhook_enabled,
        "webhook_url": s.webhook_url,
        "min_severity": s.min_severity,
    }


def _get_or_create(db: Session, user: str) -> NotificationSettings:
    settings = (
        db.query(NotificationSettings)
        .filter(NotificationSettings.owner_email == user)
        .first()
    )
    if settings is None:
        settings = NotificationSettings(id=str(uuid.uuid4()), owner_email=user)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@router.get("/notifications")
def get_notification_settings(
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> dict[str, Any]:
    return _serialize(_get_or_create(db, user))


@router.put("/notifications")
def update_notification_settings(
    payload: NotificationSettingsUpdate,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> dict[str, Any]:
    settings = _get_or_create(db, user)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(settings, field, value)
    db.commit()
    db.refresh(settings)
    return _serialize(settings)


@router.post("/notifications/test")
def send_test_notification(
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> dict[str, Any]:
    """Fire a sample alert through every enabled channel and report the result.

    Bypasses the severity threshold (this is an explicit user-triggered test) and
    reports per-channel success/error so misconfiguration is immediately visible.
    """
    settings = _get_or_create(db, user)
    sample = Alert(
        id="test",
        owner_email=user,
        target="example.com",
        scan_id=None,
        type="test",
        severity="info",
        message="EASM test alert — your notification settings are working.",
        read=False,
        created_at=datetime.now(timezone.utc),
    )

    results: dict[str, Any] = {}
    if settings.email_enabled:
        results["email"] = _run_channel(notifications.send_email, settings, sample)
    if settings.webhook_enabled and settings.webhook_url:
        results["webhook"] = _run_channel(notifications.send_webhook, settings, sample)
    if not results:
        return {"detail": "No channels enabled.", "channels": {}}
    return results


def _run_channel(fn, settings: NotificationSettings, alert: Alert) -> dict[str, Any]:
    try:
        fn(settings, alert)
        return {"ok": True, "error": None}
    except Exception as exc:  # report, don't raise — this is a diagnostic action
        return {"ok": False, "error": str(exc)}
