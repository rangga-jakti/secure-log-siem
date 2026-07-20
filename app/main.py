from fastapi import FastAPI

from app.database import Base, engine
from app.routers import auth_router, ingest, events, alerts

# For an MVP, create_all on startup is fine. A real deployment would use
# Alembic migrations instead so schema changes are versioned and reversible.
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Secure Log SIEM",
    description=(
        "Minimal SIEM-style backend: ingest security/log events, detect threats "
        "via a real-time rule engine plus a periodic IsolationForest anomaly scan, "
        "and query events/alerts through a REST API."
    ),
    version="0.1.0",
)

app.include_router(auth_router.router)
app.include_router(ingest.router)
app.include_router(events.router)
app.include_router(alerts.router)


@app.get("/health", tags=["meta"])
def health_check():
    return {"status": "ok"}
