"""
Central configuration. Values are pulled from environment variables / .env,
so nothing sensitive is hardcoded and the same codebase works in dev,
docker-compose, and a real deployment just by swapping env vars.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # sqlite by default so `git clone && pip install -r requirements.txt && run` just works.
    # Point DATABASE_URL at postgres in docker-compose / production.
    database_url: str = "sqlite:///./siem.db"

    secret_key: str = "change-me-in-production-this-is-not-secure"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Shared-secret key required on the /ingest endpoint. Separate from user JWT
    # auth because log-shipping agents are machines, not humans with passwords.
    ingest_api_key: str = "dev-ingest-key-change-me"

    # Rule engine thresholds
    brute_force_attempt_threshold: int = 5
    brute_force_window_seconds: int = 60
    port_scan_port_threshold: int = 10
    port_scan_window_seconds: int = 30

    # Anomaly detector needs a minimum number of historical events per source
    # before it trusts its own scoring (cold-start problem).
    anomaly_min_events_for_scoring: int = 50


settings = Settings()
