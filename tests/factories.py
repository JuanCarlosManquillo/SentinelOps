"""Constructores de objetos de prueba con valores por defecto razonables."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sentinelops.domain.models import Anomaly, Event, EventKind, Severity, TimeWindow

T0 = datetime(2026, 10, 1, 10, 0, tzinfo=UTC)


def make_event(
    n: int = 0,
    *,
    service: str = "checkout",
    status: int = 200,
    latency: float = 100.0,
    at: datetime = T0,
    **extra: Any,
) -> Event:
    is_error = status >= 500
    return Event(
        event_id=f"{service}-{n:05d}",
        service=service,
        kind=EventKind.HTTP_ERROR if is_error else EventKind.LOG,
        severity=Severity.ERROR if is_error else Severity.INFO,
        occurred_at=at + timedelta(seconds=n % 60),
        attributes={"http.status_code": status, "latency_ms": latency, **extra},
    )


def make_anomaly(
    service: str = "checkout", minute: int = 0, evidence: tuple[str, ...] = ("e1",)
) -> Anomaly:
    return Anomaly(
        service=service,
        detector="threshold",
        signal="error_rate",
        window=TimeWindow.starting_at(T0 + timedelta(minutes=minute), 60),
        score=2.0,
        observed=0.4,
        expected=0.2,
        evidence_ids=evidence,
    )
