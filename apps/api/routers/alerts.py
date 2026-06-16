from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session

from auth import get_current_user
from db.models import Alert
from deps import get_db
from utils import format_datetime

router = APIRouter()


def _serialize(a: Alert) -> dict[str, Any]:
    return {
        "id": a.id,
        "target": a.target,
        "scan_id": a.scan_id,
        "type": a.type,
        "severity": a.severity,
        "message": a.message,
        "read": a.read,
        "created_at": format_datetime(a.created_at),
    }


@router.get("")
def list_alerts(
    unread_only: bool = False,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> list[dict[str, Any]]:
    query = db.query(Alert).filter(Alert.owner_email == user)
    if unread_only:
        query = query.filter(Alert.read.is_(False))
    alerts = query.order_by(desc(Alert.created_at)).limit(100).all()
    return [_serialize(a) for a in alerts]


@router.post("/{alert_id}/read")
def mark_alert_read(
    alert_id: str,
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> dict[str, bool]:
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.owner_email == user).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.read = True
    db.commit()
    return {"read": True}


@router.post("/read-all")
def mark_all_read(
    db: Session = Depends(get_db),
    user: str = Depends(get_current_user),
) -> dict[str, int]:
    updated = (
        db.query(Alert)
        .filter(Alert.owner_email == user, Alert.read.is_(False))
        .update({Alert.read: True}, synchronize_session=False)
    )
    db.commit()
    return {"updated": updated}
