"""
Statistical anomaly detection, deliberately separated from the rule engine.

Design decision worth calling out: rules run per-event, in real time, because
"5 failed logins in 60s" is meaningful with zero context. IsolationForest is
NOT run per-event — an anomaly score is only meaningful *relative to a
population*. So this module works as a periodic batch scan: it aggregates
recent behavior per source_ip into a feature vector, fits IsolationForest
across all sources at once, and flags the outliers. Triggered via an admin
endpoint or a cron/script, not on every ingest call.
"""
from datetime import datetime, timedelta, timezone

import pandas as pd
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session
from sqlalchemy import func

from app import models
from app.config import settings


def build_feature_table(db: Session, lookback_hours: int = 24) -> pd.DataFrame:
    """
    One row per source_ip, aggregated over the lookback window. Features are
    intentionally simple/interpretable so a flagged row is explainable to a
    human analyst, not a black box.
    """
    window_start = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    rows = (
        db.query(
            models.Event.source_ip,
            func.count(models.Event.id).label("event_count"),
            func.count(func.distinct(models.Event.event_type)).label("distinct_event_types"),
            func.count(func.distinct(models.Event.destination_port)).label("distinct_ports"),
        )
        .filter(models.Event.received_at >= window_start, models.Event.source_ip.isnot(None))
        .group_by(models.Event.source_ip)
        .all()
    )

    # login_failed ratio computed separately for SQLite/Postgres portability
    # (avoiding boolean-to-int casting differences between dialects).
    failed_counts = dict(
        db.query(models.Event.source_ip, func.count(models.Event.id))
        .filter(
            models.Event.received_at >= window_start,
            models.Event.source_ip.isnot(None),
            models.Event.event_type == "login_failed",
        )
        .group_by(models.Event.source_ip)
        .all()
    )

    data = []
    for r in rows:
        failed = failed_counts.get(r.source_ip, 0)
        data.append(
            {
                "source_ip": r.source_ip,
                "event_count": r.event_count,
                "distinct_event_types": r.distinct_event_types,
                "distinct_ports": r.distinct_ports,
                "failed_login_ratio": failed / r.event_count if r.event_count else 0,
            }
        )
    return pd.DataFrame(data)


def scan_for_anomalies(db: Session, lookback_hours: int = 24) -> list[models.Alert]:
    """
    Fits a fresh IsolationForest on the current feature table and returns
    Alert objects (not yet committed) for source_ips flagged as outliers.
    """
    df = build_feature_table(db, lookback_hours=lookback_hours)

    if len(df) < 5:
        # Not enough distinct sources to establish a meaningful population.
        return []

    feature_cols = ["event_count", "distinct_event_types", "distinct_ports", "failed_login_ratio"]
    X = df[feature_cols].values

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
    )
    df["anomaly_score"] = model.fit_predict(X)  # -1 = outlier, 1 = normal
    df["score_raw"] = model.decision_function(X)  # lower = more anomalous

    outliers = df[df["anomaly_score"] == -1].sort_values("score_raw")

    alerts = []
    for _, row in outliers.iterrows():
        alerts.append(
            models.Alert(
                rule_name="anomaly_ml",
                severity=models.Severity.medium,
                description=(
                    f"Source {row.source_ip} flagged as statistical outlier over last "
                    f"{lookback_hours}h — {int(row.event_count)} events, "
                    f"{int(row.distinct_ports)} distinct ports, "
                    f"{row.failed_login_ratio:.0%} failed-login ratio "
                    f"(isolation score {row.score_raw:.3f})"
                ),
                source_ip=row.source_ip,
            )
        )
    return alerts
