"""Generador de datos sintéticos con incidentes etiquetados (RF-04).

Misma semilla → mismo dataset. Las etiquetas (`labels`) son la verdad de referencia
que usa la evaluación para medir precisión, recall, latencia y acierto de causa.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sentinelops.domain.models import Deployment, Event, EventKind, Severity

IncidentType = Literal["bad_deployment", "latency_spike", "dependency_outage"]


@dataclass(frozen=True, slots=True)
class IncidentLabel:
    type: IncidentType
    service: str
    start: datetime
    end: datetime
    root_cause: str


@dataclass(slots=True)
class Dataset:
    events: list[Event] = field(default_factory=list)
    deployments: list[Deployment] = field(default_factory=list)
    labels: list[IncidentLabel] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ScenarioConfig:
    seed: int = 42
    start: datetime = datetime(2026, 10, 1, 10, 0, tzinfo=UTC)
    minutes: int = 120
    services: tuple[str, ...] = ("checkout", "payments", "catalog")
    requests_per_minute: int = 30
    baseline_error_rate: float = 0.02
    baseline_latency_ms: float = 120.0


def generate(config: ScenarioConfig | None = None) -> Dataset:
    config = config or ScenarioConfig()
    # Datos sintéticos con semilla: no se usa para criptografía.
    rng = random.Random(config.seed)  # nosec B311
    data = Dataset()
    s0 = config.start
    # Tres incidentes fijos y separados; la semilla cambia el ruido, no la verdad.
    plan: list[tuple[IncidentType, str, int, int]] = [
        ("bad_deployment", config.services[0], 30, 8),
        ("latency_spike", config.services[1 % len(config.services)], 60, 6),
        ("dependency_outage", config.services[2 % len(config.services)], 95, 5),
    ]
    for kind, service, at, duration in plan:
        start = s0 + timedelta(minutes=at)
        end = start + timedelta(minutes=duration)
        if kind == "bad_deployment":
            deployed = start - timedelta(minutes=3)
            data.deployments.append(Deployment(service, "v2.4.1", deployed))
            cause = "deployment:" + service + ":v2.4.1"
        elif kind == "latency_spike":
            cause = "latency:" + service
        else:
            cause = "dependency:" + service
        data.labels.append(IncidentLabel(kind, service, start, end, cause))

    for minute in range(config.minutes):
        minute_start = s0 + timedelta(minutes=minute)
        for service in config.services:
            active = _active_label(data.labels, service, minute_start)
            for n in range(config.requests_per_minute):
                ts = minute_start + timedelta(seconds=rng.uniform(0, 59.999))
                data.events.append(_request_event(rng, config, service, ts, n, active))
    data.events.sort(key=lambda e: (e.occurred_at, e.event_id))
    return data


def _active_label(labels: list[IncidentLabel], service: str, ts: datetime) -> IncidentLabel | None:
    return next((lb for lb in labels if lb.service == service and lb.start <= ts < lb.end), None)


def _request_event(
    rng: random.Random,
    config: ScenarioConfig,
    service: str,
    ts: datetime,
    n: int,
    active: IncidentLabel | None,
) -> Event:
    error_rate = config.baseline_error_rate
    latency = rng.gauss(config.baseline_latency_ms, config.baseline_latency_ms * 0.2)
    error_status = 500
    if active is not None:
        if active.type == "bad_deployment":
            error_rate, error_status = 0.45, 500
        elif active.type == "latency_spike":
            latency = rng.gauss(1800, 300)
        else:  # dependency_outage
            error_rate, error_status = 0.7, 503
    is_error = rng.random() < error_rate
    status = error_status if is_error else 200
    attributes: dict[str, Any] = {
        "http.route": "/api",
        "http.status_code": status,
        "latency_ms": round(max(latency, 1.0), 1),
    }
    return Event(
        event_id=f"{service}-{ts:%Y%m%dT%H%M%S}-{n:03d}",
        service=service,
        kind=EventKind.HTTP_ERROR if is_error else EventKind.LOG,
        severity=Severity.ERROR if is_error else Severity.INFO,
        occurred_at=ts,
        message=f"GET /api returned {status}",
        attributes=attributes,
    )
