import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Column, Integer, String, DateTime, Float, ForeignKey, Text, Boolean, Enum
)
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Severity(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Event(Base):
    """
    A single raw security/log event as reported by an agent
    (e.g. windows-security-monitor, a firewall, an app's auth layer).
    Kept intentionally generic so any log source can be normalized into it.
    """
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String(128), index=True, nullable=False)       # e.g. "host-01", "edge-firewall"
    event_type = Column(String(64), index=True, nullable=False)    # e.g. "login_failed", "port_scan", "process_start"
    source_ip = Column(String(45), index=True, nullable=True)      # IPv4/IPv6
    destination_port = Column(Integer, nullable=True)
    username = Column(String(128), nullable=True)                  # subject of the event, if applicable
    message = Column(Text, nullable=True)
    raw_payload = Column(Text, nullable=True)                      # original JSON, for forensics
    received_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    alerts = relationship("Alert", back_populates="triggering_event")


class Alert(Base):
    """
    Produced by the detection layer (rules and/or anomaly model) when
    one or more events cross a threshold or look statistically unusual.
    """
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    rule_name = Column(String(128), nullable=False)
    severity = Column(Enum(Severity), default=Severity.medium, nullable=False)
    description = Column(Text, nullable=False)
    source_ip = Column(String(45), index=True, nullable=True)
    resolved = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    triggering_event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    triggering_event = relationship("Event", back_populates="alerts")
