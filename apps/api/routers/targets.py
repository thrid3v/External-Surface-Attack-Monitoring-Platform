from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session

from db.models import Scan
from deps import get_db

router = APIRouter()


def _format_datetime(value: datetime | None) -> str | None:
    return value.astimezone(timezone.utc).isoformat() if value else None


@router.get("")
def list_targets(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    scans = (
        db.query(Scan)
        .order_by(Scan.target, desc(Scan.started_at), desc(Scan.created_at))
        .all()
    )
    summaries: dict[str, dict[str, Any]] = {}

    for scan in scans:
        if scan.target not in summaries:
            summaries[scan.target] = {
                "target": scan.target,
                "last_scanned": _format_datetime(scan.started_at or scan.created_at),
                "last_risk_score": scan.risk_score,
                "last_risk_label": scan.risk_label,
                "total_scans": 0,
            }
        summaries[scan.target]["total_scans"] += 1

    return list(summaries.values())


@router.get("/{target}/history")
def get_target_history(target: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    scans = (
        db.query(Scan)
        .filter(Scan.target == target)
        .order_by(desc(Scan.started_at), desc(Scan.created_at))
        .all()
    )
    if not scans:
        raise HTTPException(status_code=404, detail="Target history not found")

    return {
        "target": target,
        "scans": [
            {
                "scan_id": scan.id,
                "status": scan.status,
                "risk_score": scan.risk_score,
                "risk_label": scan.risk_label,
                "started_at": _format_datetime(scan.started_at),
                "completed_at": _format_datetime(scan.completed_at),
            }
            for scan in scans
        ],
    }


@router.get("/{target}/latest")
def get_latest_complete_scan(target: str, db: Session = Depends(get_db)) -> Any:
    scan = (
        db.query(Scan)
        .filter(Scan.target == target, Scan.status == "complete")
        .order_by(desc(Scan.started_at), desc(Scan.created_at))
        .first()
    )
    if scan is None or scan.result is None:
        raise HTTPException(status_code=404, detail="No completed scan found for this target")

    return scan.result
