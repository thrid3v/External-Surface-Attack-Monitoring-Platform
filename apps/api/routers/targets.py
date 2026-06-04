from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from db.models import Scan
from deps import get_db
from utils import format_datetime

router = APIRouter()


@router.get("")
def list_targets(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Return one summary row per unique target, ordered by most recently scanned.

    Uses a SQL subquery to avoid loading the full scan history into Python
    memory — only the latest scan per target is fetched for the summary
    columns, and a count query gives total scans per target.
    """
    # Subquery: for each target get the most recent scan's data.
    latest_per_target = (
        db.query(
            Scan.target,
            func.max(Scan.started_at).label("last_started_at"),
            func.max(Scan.created_at).label("last_created_at"),
            func.count(Scan.id).label("total_scans"),
        )
        .group_by(Scan.target)
        .subquery()
    )

    # Join back to Scans to pull risk score/label from the most recent scan.
    # We do this as a separate query per row to keep the SQL simple and avoid
    # complex window functions that may not be portable.
    targets_meta = db.query(latest_per_target).all()

    results: list[dict[str, Any]] = []
    for row in targets_meta:
        latest_scan = (
            db.query(Scan)
            .filter(Scan.target == row.target)
            .order_by(desc(Scan.started_at), desc(Scan.created_at))
            .first()
        )
        results.append(
            {
                "target": row.target,
                "last_scanned": format_datetime(
                    row.last_started_at or row.last_created_at
                ),
                "last_risk_score": latest_scan.risk_score if latest_scan else None,
                "last_risk_label": latest_scan.risk_label if latest_scan else None,
                "total_scans": row.total_scans,
            }
        )

    results.sort(
        key=lambda r: r["last_scanned"] or "",
        reverse=True,
    )
    return results


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
                "started_at": format_datetime(scan.started_at),
                "completed_at": format_datetime(scan.completed_at),
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
