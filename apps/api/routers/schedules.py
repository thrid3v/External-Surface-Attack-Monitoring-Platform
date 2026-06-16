import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from auth import get_current_user
from constants import PORT_PROFILES
from db.models import Schedule
from deps import get_db
from utils import format_datetime

router = APIRouter()


class ScheduleCreate(BaseModel):
    target: str
    port_range: str = "1-1000"
    profile: str | None = None
    modules: list[str] | None = None
    interval_minutes: int = Field(1440, ge=5)


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
    target = payload.target.strip().lower()
    if not target:
        raise HTTPException(status_code=422, detail="Target is required")

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
