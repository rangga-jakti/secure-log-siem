from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app import models, schemas, auth
from app.database import get_db
from app.detection.anomaly import scan_for_anomalies

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=List[schemas.AlertOut])
def list_alerts(
    resolved: Optional[bool] = None,
    severity: Optional[models.Severity] = None,
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
    _user: models.User = Depends(auth.get_current_user),
):
    query = db.query(models.Alert)
    if resolved is not None:
        query = query.filter(models.Alert.resolved == resolved)
    if severity is not None:
        query = query.filter(models.Alert.severity == severity)
    return query.order_by(models.Alert.created_at.desc()).limit(limit).all()


@router.patch("/{alert_id}/resolve", response_model=schemas.AlertOut)
def resolve_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    _user: models.User = Depends(auth.get_current_user),
):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    alert.resolved = True
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/scan-anomalies", response_model=List[schemas.AlertOut])
def trigger_anomaly_scan(
    lookback_hours: int = Query(default=24, ge=1, le=168),
    db: Session = Depends(get_db),
    _admin: models.User = Depends(auth.require_admin),
):
    """
    Admin-only: runs the IsolationForest batch scan on demand. In production
    this would also run on a schedule (cron / Celery beat) — exposing it as
    an endpoint too makes it demoable and testable without waiting for a timer.
    """
    new_alerts = scan_for_anomalies(db, lookback_hours=lookback_hours)
    for alert in new_alerts:
        db.add(alert)
    db.commit()
    for alert in new_alerts:
        db.refresh(alert)
    return new_alerts
