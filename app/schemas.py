from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, ConfigDict, Field

from app.models import Severity


# ---------- Auth ----------

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    is_admin: bool


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---------- Events ----------

class EventIn(BaseModel):
    """What a log-shipping agent sends to POST /ingest."""
    source: str = Field(max_length=128)
    event_type: str = Field(max_length=64)
    source_ip: Optional[str] = Field(default=None, max_length=45)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    username: Optional[str] = Field(default=None, max_length=128)
    message: Optional[str] = None
    raw_payload: Optional[dict] = None


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    source: str
    event_type: str
    source_ip: Optional[str]
    destination_port: Optional[int]
    username: Optional[str]
    message: Optional[str]
    received_at: datetime


class IngestResult(BaseModel):
    accepted: int
    alerts_triggered: int
    alert_ids: List[int] = []


# ---------- Alerts ----------

class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule_name: str
    severity: Severity
    description: str
    source_ip: Optional[str]
    resolved: bool
    created_at: datetime
    triggering_event_id: Optional[int]
