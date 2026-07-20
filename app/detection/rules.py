"""
Rule-based detection. Deliberately simple and explainable — every alert this
layer produces can be traced to one plain-English condition. This is what
runs on every single ingested event, before the heavier anomaly model.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from app import models
from app.config import settings


def check_brute_force(db: Session, event: models.Event) -> Optional[models.Alert]:
    """
    N+ failed logins from the same source IP within a rolling time window
    = classic brute-force / credential-stuffing pattern.
    """
    if event.event_type != "login_failed" or not event.source_ip:
        return None

    window_start = datetime.now(timezone.utc) - timedelta(
        seconds=settings.brute_force_window_seconds
    )
    recent_failures = (
        db.query(func.count(models.Event.id))
        .filter(
            models.Event.event_type == "login_failed",
            models.Event.source_ip == event.source_ip,
            models.Event.received_at >= window_start,
        )
        .scalar()
    )

    if recent_failures >= settings.brute_force_attempt_threshold:
        return models.Alert(
            rule_name="brute_force_login",
            severity=models.Severity.high,
            description=(
                f"{recent_failures} failed login attempts from {event.source_ip} "
                f"within {settings.brute_force_window_seconds}s"
            ),
            source_ip=event.source_ip,
            triggering_event=event,
        )
    return None


def check_port_scan(db: Session, event: models.Event) -> Optional[models.Alert]:
    """
    A single source IP touching many distinct destination ports in a short
    window looks like reconnaissance (nmap-style scanning), not normal traffic.
    """
    if event.event_type != "connection_attempt" or not event.source_ip:
        return None

    window_start = datetime.now(timezone.utc) - timedelta(
        seconds=settings.port_scan_window_seconds
    )
    distinct_ports = (
        db.query(func.count(func.distinct(models.Event.destination_port)))
        .filter(
            models.Event.event_type == "connection_attempt",
            models.Event.source_ip == event.source_ip,
            models.Event.received_at >= window_start,
        )
        .scalar()
    )

    if distinct_ports >= settings.port_scan_port_threshold:
        return models.Alert(
            rule_name="port_scan",
            severity=models.Severity.medium,
            description=(
                f"{event.source_ip} touched {distinct_ports} distinct ports "
                f"within {settings.port_scan_window_seconds}s"
            ),
            source_ip=event.source_ip,
            triggering_event=event,
        )
    return None


def check_privileged_process(db: Session, event: models.Event) -> Optional[models.Alert]:
    """
    Flags process-start events that name a small set of tools commonly used
    for credential dumping / lateral movement (e.g. from an EDR-style feed
    like windows-security-monitor). Static list kept short and explicit on
    purpose — this is a tripwire, not a full detection product.
    """
    watched_process_keywords = {"mimikatz", "psexec", "procdump", "netcat", "nc.exe"}

    if event.event_type != "process_start" or not event.message:
        return None

    lowered = event.message.lower()
    hit = next((kw for kw in watched_process_keywords if kw in lowered), None)
    if hit:
        return models.Alert(
            rule_name="suspicious_process",
            severity=models.Severity.critical,
            description=f"Watched process pattern '{hit}' seen on {event.source}: {event.message}",
            source_ip=event.source_ip,
            triggering_event=event,
        )
    return None


# Every rule runs in order on every ingested event. Order doesn't matter here
# since each rule is independent, but keeping them in one list makes adding
# a new rule a one-line change instead of touching the router.
ALL_RULES = [check_brute_force, check_port_scan, check_privileged_process]


def run_rules(db: Session, event: models.Event) -> list[models.Alert]:
    triggered = []
    for rule in ALL_RULES:
        alert = rule(db, event)
        if alert:
            triggered.append(alert)
    return triggered
