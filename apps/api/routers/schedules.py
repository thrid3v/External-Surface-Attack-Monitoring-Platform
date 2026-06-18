import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from auth import get_current_user
from constants import MODULE_ORDER, PORT_PROFILES
from db.models import Scan, Schedule
from deps import get_db
from services import net_guard
from services.rate_limit import enforce_scan_rate_limit
from utils import format_datetime
from workers.scan_worker import run_scan

router = APIRouter()


class ScheduleCreate(BaseModel):
    target: str
    port_range: str = "1-1000"
    profile: str | None = None
    modules: list[str] | None = None
    interval_minutes: int = Field(1440, ge=5)
    i_own_this_target: bool = Field(False)


def _serialize(s: Schedule) -> dict[str, Any]:
    return {
        "id": s.id,
        "target": s.target,
        "port_range": s.port_range,
        "profile": s.profile,
        "modules": s.modules_list,
        "interval_minutes": s.interval_minutes,
        "enabled": s.enabled,
        "next_run_at": format_datetime(s.next_run_at),
        "last_run_at": format_datetime(s.last_run_at),
        "created_at": format_datetime(s.created_at),
    }


def _owned(db: Session, schedule_id: str, user: str) -> Schedule:
    schedule = (
        db.query(Schedule)
        .filter(Schedule.id == schedule_id, Schedule.owner_email == user)
        .first()
    )
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return schedule


@router.post("")
def create_schedule(
    payload: ScheduleCreate,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> dict[str, Any]:
    if not payload.i_own_this_target:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you own or have permission to scan this target.",
        )
    # Same SSRF target policy as one-off scans (blocks private/internal hosts
    # unless ALLOW_PRIVATE_TARGETS is set).
    try:
        target = net_guard.validate_scan_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    port_range = payload.port_range
    if payload.profile:
        if payload.profile not in PORT_PROFILES:
            raise HTTPException(status_code=422, detail=f"Unknown port profile '{payload.profile}'")
        port_range = PORT_PROFILES[payload.profile]

    now = datetime.now(timezone.utc)
    schedule = Schedule(
        id=str(uuid.uuid4()),
        owner_email=user,
        target=target,
        port_range=port_range,
        profile=payload.profile,
        modules=json.dumps(payload.modules) if payload.modules else None,
        interval_minutes=payload.interval_minutes,
        enabled=True,
        next_run_at=now,  # eligible on the next dispatcher tick
        last_run_at=None,
        created_at=now,
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return _serialize(schedule)


@router.get("")
def list_schedules(
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> list[dict[str, Any]]:
    schedules = (
        db.query(Schedule)
        .filter(Schedule.owner_email == user)
        .order_by(desc(Schedule.created_at))
        .all()
    )
    return [_serialize(s) for s in schedules]


@router.post("/{schedule_id}/toggle")
def toggle_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> dict[str, Any]:
    schedule = _owned(db, schedule_id, user)
    schedule.enabled = not schedule.enabled
    db.commit()
    db.refresh(schedule)
    return _serialize(schedule)


@router.post("/{schedule_id}/run")
def run_schedule_now(
    schedule_id: str,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> dict[str, str]:
    """Trigger a schedule immediately, reusing its stored scan configuration."""
    schedule = _owned(db, schedule_id, user)
    enforce_scan_rate_limit(db, user)
    now = datetime.now(timezone.utc)
    scan_id = str(uuid.uuid4())
    port_range = schedule.port_range or "1-1000"
    modules = schedule.modules_list or list(MODULE_ORDER)

    scan = Scan(
        id=scan_id,
        owner_email=user,
        target=schedule.target,
        status="pending",
        port_range=port_range,
        created_at=now,
    )
    db.add(scan)
    schedule.last_run_at = now
    schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
    db.commit()

    run_scan.apply_async(args=[scan_id, schedule.target, port_range, modules], task_id=scan_id)
    return {"scan_id": scan_id, "status": "pending"}


@router.delete("/{schedule_id}")
def delete_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> dict[str, bool]:
    schedule = _owned(db, schedule_id, user)
    db.delete(schedule)
    db.commit()
    return {"deleted": True}
