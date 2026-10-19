"""Modelo de dominio: entidades inmutables y objetos valor.

Este modulo solo usa la biblioteca estándar.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Any

from sentinelops.domain.errors import InvalidTransition, InvalidValue

#  objetos valor


class Severity(IntEnum):
    """Severidad ordenada: permite comparar `sev >= Severity.ERROR`."""

    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError as exc:
            raise InvalidValue(f"severidad desconocida: {value!r}") from exc


class EventKind(StrEnum):
    LOG = "log"
    METRIC = "metric"
    HTTP_ERROR = "http_error"


@dataclass(frozen=True, slots=True)
class TimeWindow:
    """Intervalo semiabierto [start, end) con zona horaria."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise InvalidValue("la ventana necesita marcas de tiempo con zona horaria")
        if self.start >= self.end:
            raise InvalidValue("el inicio de la ventana debe ser anterior al fin")

    @classmethod
    def starting_at(cls, start: datetime, seconds: int) -> TimeWindow:
        return cls(start, start + timedelta(seconds=seconds))

    def contains(self, ts: datetime) -> bool:
        return self.start <= ts < self.end

    def next(self) -> TimeWindow:
        return TimeWindow(self.end, self.end + (self.end - self.start))


@dataclass(frozen=True, slots=True)
class Confidence:
    value: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise InvalidValue("la confianza debe estar entre 0 y 1")


#  entidades


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    service: str
    kind: EventKind
    severity: Severity
    occurred_at: datetime
    message: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)
    trace_id: str | None = None

    @property
    def http_status(self) -> int | None:
        # Caso de uso: "¿que codigo HTTP devolvio esta peticion?"
        value = self.attributes.get("http.status_code")
        return int(value) if isinstance(value, int | float) else None

    @property
    def latency_ms(self) -> float | None:
        # Caso de uso: "¿cuánto tardó esta peticion?"
        value = self.attributes.get("latency_ms")
        return float(value) if isinstance(value, int | float) else None

    @property
    def is_error(self) -> bool:
        # Caso de uso: "¿debería alertar este evento?"
        status = self.http_status
        return self.severity >= Severity.ERROR or (status is not None and status >= 500)


@dataclass(frozen=True, slots=True)
class Deployment:
    service: str
    version: str
    deployed_at: datetime


@dataclass(frozen=True, slots=True)
class Anomaly:
    service: str
    detector: str
    signal: str
    window: TimeWindow
    score: float
    observed: float
    expected: float
    evidence_ids: tuple[str, ...]

    @property
    def key(self) -> tuple[str, str, str, datetime]:
        """Clave idempotente: una anomalía por servicio, detector, señal y ventana."""
        return (self.service, self.detector, self.signal, self.window.start)


@dataclass(frozen=True, slots=True)
class Hypothesis:
    cause: str
    confidence: Confidence
    evidence: tuple[str, ...]
    rule: str
    recommendation: str = ""

    def __post_init__(self) -> None:
        if not self.evidence:
            # RF-10: toda hipótesis debe apuntar a evidencias concretas.
            raise InvalidValue("una hipótesis necesita al menos una evidencia")


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


_ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset({IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED}),
    IncidentStatus.INVESTIGATING: frozenset({IncidentStatus.RESOLVED}),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.OPEN}),
}


@dataclass(frozen=True, slots=True)
class Incident:
    """Raíz del agregado: agrupa anomalías e hipótesis."""

    id: uuid.UUID
    status: IncidentStatus
    anomalies: tuple[Anomaly, ...]
    hypotheses: tuple[Hypothesis, ...] = ()

    @classmethod
    def open_from(cls, anomaly: Anomaly) -> Incident:
        return cls(id=uuid.uuid4(), status=IncidentStatus.OPEN, anomalies=(anomaly,))

    @property
    def services(self) -> frozenset[str]:
        return frozenset(a.service for a in self.anomalies)

    @property
    def started_at(self) -> datetime:
        return min(a.window.start for a in self.anomalies)

    @property
    def last_seen_at(self) -> datetime:
        return max(a.window.end for a in self.anomalies)

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for anomaly in self.anomalies:
            seen.update(dict.fromkeys(anomaly.evidence_ids))
        return tuple(seen)

    def with_anomaly(self, anomaly: Anomaly) -> Incident:
        if any(a.key == anomaly.key for a in self.anomalies):
            return self  # idempotente : no agregamos duplicados|
        return replace(self, anomalies=(*self.anomalies, anomaly))

    def with_hypotheses(self, hypotheses: tuple[Hypothesis, ...]) -> Incident:
        ordered = tuple(sorted(hypotheses, key=lambda h: h.confidence.value, reverse=True))
        return replace(self, hypotheses=ordered)

    def transition_to(self, status: IncidentStatus) -> Incident:
        if status not in _ALLOWED_TRANSITIONS[self.status]:
            raise InvalidTransition(self.status.value, status.value)
        return replace(self, status=status)
