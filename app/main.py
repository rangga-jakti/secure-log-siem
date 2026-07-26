from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import auth_router, ingest, events, alerts

# Schema is managed by Alembic migrations (see alembic/), not create_all().
# Run `alembic upgrade head` before starting the app for the first time.

app = FastAPI(
    title="Secure Log SIEM",
    description=(
        "Minimal SIEM-style backend: ingest security/log events, detect threats "
        "via a real-time rule engine plus a periodic IsolationForest anomaly scan, "
        "and query events/alerts through a REST API."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(ingest.router)
app.include_router(events.router)
app.include_router(alerts.router)


@app.get("/health", tags=["meta"])
def health_check():
    return {"status": "ok"}
