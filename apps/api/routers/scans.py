import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from auth import get_current_user
from constants import MODULE_ORDER, PORT_PROFILES
from db.models import Scan
from deps import get_db
from services.diff import diff_reports
from utils import format_datetime
from workers.scan_worker import run_scan

router = APIRouter()

VALID_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9.-]+$")


class ScanCreate(BaseModel):
    target: str
    port_range: str = "1-1000"
    profile: str | None = None
    modules: list[str] | None = None
    i_own_this_target: bool = Field(False)


class ScanQueuedResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    current_module: str | None = None
    modules_complete: list[str] = Field(default_factory=list)
    started_at: str | None = None


class ScanSummary(BaseModel):
    scan_id: str
    target: str
    status: str
    risk_score: int | None
    risk_label: str | None
    started_at: str | None


def _validate_and_clean_target(raw_target: str) -> str:
    if not raw_target or not raw_target.strip():
        raise HTTPException(status_code=422, detail="Target is required")

    target = raw_target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path

    target = target.split("/", 1)[0].strip().lower()
    target = target.split(":", 1)[0]
    if target.startswith("www."):
        target = target[4:]

    if not target or " " in target:
        raise HTTPException(status_code=422, detail="Invalid target format")
    if not VALID_TARGET_PATTERN.fullmatch(target):
        raise HTTPException(status_code=422, detail="Invalid target format")
    if "." not in target and not target.replace(".", "").isdigit():
        raise HTTPException(status_code=422, detail="Invalid target format")
    return target


def _get_modules_complete(current_module: str | None, status: str) -> list[str]:
    """Return modules that have finished running.

    ``current_module`` is the module *currently executing* (set by the worker
    before it starts that module).  Everything before it in MODULE_ORDER is
    therefore complete.  When the scan is finished, all modules are complete.
    """
    if status == "complete":
        return MODULE_ORDER.copy()
    if not current_module:
        return []
    completed = []
    for module in MODULE_ORDER:
        if module == current_module:
            # current_module is still running — stop here
            break
        completed.append(module)
    return completed


@router.post("", response_model=ScanQueuedResponse)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> ScanQueuedResponse:
    if not payload.i_own_this_target:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you own or have permission to scan this target.",
        )

    target = _validate_and_clean_target(payload.target)
    # A named profile (if valid) resolves to a port range; an explicit
    # port_range in the request still takes precedence when no profile is given.
    if payload.profile:
        if payload.profile not in PORT_PROFILES:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown port profile '{payload.profile}'. Valid: {', '.join(PORT_PROFILES)}",
            )
        port_range = PORT_PROFILES[payload.profile]
    else:
        port_range = payload.port_range
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        owner_email=user,
        target=target,
        status="pending",
        port_range=port_range,
        created_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    run_scan.delay(scan_id, target, port_range, payload.modules or list(MODULE_ORDER))

    return ScanQueuedResponse(
        scan_id=scan_id,
        status="pending",
        message="Scan queued. Poll /api/scans/{scan_id} for results.",
    )


@router.get("/{scan_id}")
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> Any:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_email == user).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in {"pending", "running"}:
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "started_at": format_datetime(scan.started_at),
        }
    if scan.status == "failed":
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "error": scan.error_message,
        }
    if scan.status == "complete":
        report = scan.result
        if report is None:
            raise HTTPException(status_code=500, detail="Scan result is unavailable")
        return report
    return {
        "scan_id": scan.id,
        "status": scan.status,
    }


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> ScanStatusResponse:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_email == user).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        current_module=scan.current_module,
        modules_complete=_get_modules_complete(scan.current_module, scan.status),
        started_at=format_datetime(scan.started_at),
    )


@router.get("/{scan_id}/diff")
def get_scan_diff(
    scan_id: str,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> Any:
    """Diff a completed scan against the user's previous completed scan of the
    same target (new/resolved CVEs, opened/closed ports, risk delta)."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_email == user).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "complete" or scan.result is None:
        raise HTTPException(status_code=409, detail="Scan is not complete")

    previous = (
        db.query(Scan)
        .filter(
            Scan.owner_email == user,
            Scan.target == scan.target,
            Scan.status == "complete",
            Scan.id != scan.id,
            Scan.started_at < scan.started_at,
        )
        .order_by(desc(Scan.started_at), desc(Scan.created_at))
        .first()
    )

    diff = diff_reports(previous.result if previous else None, scan.result)
    return {"scan_id": scan.id, "target": scan.target, **diff}


@router.get("", response_model=list[ScanSummary])
def list_scans(
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> list[ScanSummary]:
    scans = (
        db.query(Scan)
        .filter(Scan.owner_email == user)
        .order_by(desc(Scan.started_at), desc(Scan.created_at))
        .limit(20)
        .all()
    )

    return [
        ScanSummary(
            scan_id=scan.id,
            target=scan.target,
            status=scan.status,
            risk_score=scan.risk_score,
            risk_label=scan.risk_label,
            started_at=format_datetime(scan.started_at),
        )
        for scan in scans
    ]


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> dict[str, bool]:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.owner_email == user).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"deleted": True}
