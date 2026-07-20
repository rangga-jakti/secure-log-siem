from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app import models, schemas, auth
from app.database import get_db

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=List[schemas.EventOut])
def list_events(
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
    _user: models.User = Depends(auth.get_current_user),
):
    query = db.query(models.Event)
    if source:
        query = query.filter(models.Event.source == source)
    if event_type:
        query = query.filter(models.Event.event_type == event_type)
    if source_ip:
        query = query.filter(models.Event.source_ip == source_ip)
    if since:
        query = query.filter(models.Event.received_at >= since)
    if until:
        query = query.filter(models.Event.received_at <= until)

    return (
        query.order_by(models.Event.received_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
