import os

# Use an isolated in-memory-ish sqlite file for tests so we never touch dev data.
os.environ["DATABASE_URL"] = "sqlite:///./test_siem.db"

import pytest
from fastapi.testclient import TestClient

from app.database import Base, engine
from app.main import app
from app.config import settings
from app import models  # noqa: F401  (registers models on Base.metadata)

# Tests create the schema directly from models rather than running Alembic
# migrations — that keeps the suite fast and focused on app behavior.
# Migrations themselves are simple enough to be verified by running
# `alembic upgrade head` locally/in CI as a separate, explicit step.
Base.metadata.create_all(bind=engine)

client = TestClient(app)

ADMIN_USER = {"username": "admin_test", "password": "supersecret123"}


@pytest.fixture(scope="module", autouse=True)
def cleanup():
    yield
    # Windows keeps a file handle open on the sqlite connection until the
    # engine's pool is explicitly disposed, which blocks deleting the file
    # here (this is a no-op-safe call on other platforms too).
    engine.dispose()
    if os.path.exists("./test_siem.db"):
        os.remove("./test_siem.db")


def get_token():
    client.post("/auth/register", json=ADMIN_USER)
    resp = client.post(
        "/auth/login",
        data={"username": ADMIN_USER["username"], "password": ADMIN_USER["password"]},
    )
    return resp.json()["access_token"]


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_register_and_login():
    token = get_token()
    assert token


def test_ingest_requires_api_key():
    resp = client.post("/ingest", json={"source": "host-1", "event_type": "login_failed"})
    assert resp.status_code == 422 or resp.status_code == 401  # missing header


def test_ingest_single_event():
    resp = client.post(
        "/ingest",
        headers={"x-api-key": settings.ingest_api_key},
        json={
            "source": "host-1",
            "event_type": "login_failed",
            "source_ip": "10.0.0.5",
            "username": "root",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["accepted"] == 1


def test_brute_force_rule_triggers_alert():
    # threshold is 5 within 60s by default — fire 5 failed logins from same IP
    for _ in range(settings.brute_force_attempt_threshold):
        resp = client.post(
            "/ingest",
            headers={"x-api-key": settings.ingest_api_key},
            json={
                "source": "host-2",
                "event_type": "login_failed",
                "source_ip": "203.0.113.9",
                "username": "admin",
            },
        )
    assert resp.status_code == 201
    assert resp.json()["alerts_triggered"] >= 1

    token = get_token()
    alerts_resp = client.get("/alerts", headers={"Authorization": f"Bearer {token}"})
    assert alerts_resp.status_code == 200
    rule_names = [a["rule_name"] for a in alerts_resp.json()]
    assert "brute_force_login" in rule_names


def test_events_query_requires_auth():
    resp = client.get("/events")
    assert resp.status_code == 401


def test_events_query_with_auth():
    token = get_token()
    resp = client.get(
        "/events",
        headers={"Authorization": f"Bearer {token}"},
        params={"source_ip": "203.0.113.9"},
    )
    assert resp.status_code == 200
    assert len(resp.json()) >= 1
