"""
utils.py
--------
Shared utility helpers used across routers and other API modules.
"""

from datetime import datetime, timezone


def format_datetime(value: datetime | None) -> str | None:
    """Return an ISO 8601 UTC string for *value*, or None if value is None."""
    return value.astimezone(timezone.utc).isoformat() if value else None
