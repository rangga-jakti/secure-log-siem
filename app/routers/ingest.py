from typing import List, Union

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app import models, schemas, auth
from app.database import get_db
from app.detection.rules import run_rules

router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post("", response_model=schemas.IngestResult, status_code=status.HTTP_201_CREATED)
def ingest_events(
    payload: Union[schemas.EventIn, List[schemas.EventIn]],
    db: Session = Depends(get_db),
    _: None = Depends(auth.verify_ingest_key),
):
    """
    Accepts a single event or a batch (list) so a log-shipping agent can
    either stream events one at a time or flush a buffer periodically.
    Every event is run through the rule engine synchronously before the
    response is returned — for an MVP this keeps the system simple and the
    alert is guaranteed to exist by the time the caller gets a 201. At real
    production log volume this is the first thing you'd move to a queue
    (see README "Scaling notes").
    """
    events_in = payload if isinstance(payload, list) else [payload]

    alert_ids: list[int] = []
    for event_in in events_in:
        event = models.Event(
            source=event_in.source,
            event_type=event_in.event_type,
            source_ip=event_in.source_ip,
            destination_port=event_in.destination_port,
            username=event_in.username,
            message=event_in.message,
            raw_payload=str(event_in.raw_payload) if event_in.raw_payload else None,
        )
        db.add(event)
        db.flush()  # assigns event.id without committing, needed for FK + rules that query it

        triggered_alerts = run_rules(db, event)
        for alert in triggered_alerts:
            db.add(alert)
            db.flush()
            alert_ids.append(alert.id)

    db.commit()

    return schemas.IngestResult(
        accepted=len(events_in),
        alerts_triggered=len(alert_ids),
        alert_ids=alert_ids,
    )
