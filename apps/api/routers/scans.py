import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from db.models import Scan
from deps import get_db
from workers.scan_worker import run_scan

router = APIRouter()

VALID_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9.-]+$")
MODULE_ORDER = [
    "port_scanner",
    "cve_lookup",
    "dns_enum",
    "osint_fetcher",
    "service_probe",
]


class ScanCreate(BaseModel):
    target: str
    port_range: str = "1-1000"
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


def _format_datetime(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat() if value else None


def _get_modules_complete(current_module: str | None, status: str) -> list[str]:
    if status == "complete":
        return MODULE_ORDER.copy()
    if not current_module:
        return []
    completed = []
    for module in MODULE_ORDER:
        if module == current_module:
            break
        completed.append(module)
    return completed


@router.post("", response_model=ScanQueuedResponse)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> ScanQueuedResponse:
    if not payload.i_own_this_target:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you own or have permission to scan this target.",
        )

    target = _validate_and_clean_target(payload.target)
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        target=target,
        status="pending",
        port_range=payload.port_range,
        created_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    run_scan.delay(scan_id, target, payload.port_range, payload.modules or MODULE_ORDER)

    return ScanQueuedResponse(
        scan_id=scan_id,
        status="pending",
        message="Scan queued. Poll /api/scans/{scan_id} for results.",
    )


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> Any:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in {"pending", "running"}:
        return {
            "scan_id": scan.id,
            "status": scan.status,
            "started_at": _format_datetime(scan.started_at),
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
def get_scan_status(scan_id: str, db: Session = Depends(get_db)) -> ScanStatusResponse:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        current_module=scan.current_module,
        modules_complete=_get_modules_complete(scan.current_module, scan.status),
        started_at=_format_datetime(scan.started_at),
    )


@router.get("", response_model=list[ScanSummary])
def list_scans(db: Session = Depends(get_db)) -> list[ScanSummary]:
    scans = (
        db.query(Scan)
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
            started_at=_format_datetime(scan.started_at),
        )
        for scan in scans
    ]


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)) -> dict[str, bool]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"deleted": True}
