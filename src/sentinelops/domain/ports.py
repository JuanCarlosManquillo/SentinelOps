"""Puertos (protocolos) que la infraestructura implementa.

Protocolos pequeños y separados (principio de segregación de interfaces).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

from sentinelops.domain.models import (
    Anomaly,
    Deployment,
    Event,
    Hypothesis,
    Incident,
    TimeWindow,
)


class EventWriter(Protocol):
    async def add_many(self, events: Sequence[Event]) -> int:
        """Inserta eventos de forma idempotente y devuelve cuántos eran nuevos."""
        ...


class DeploymentWriter(Protocol):
    async def add(self, deployment: Deployment) -> uuid.UUID:
        """Registra un despliegue y devuelve su identificador."""
        ...


class EventReader(Protocol):
    async def list_window(self, window: TimeWindow) -> Sequence[Event]: ...


class Detector(Protocol):
    """Estrategia de detección: función pura de eventos a anomalías."""

    @property
    def name(self) -> str: ...

    def detect(self, events: Sequence[Event], window: TimeWindow) -> list[Anomaly]: ...


@dataclass(frozen=True, slots=True)
class DiagnosisContext:
    """Datos que una regla puede consultar, ya cargados: las reglas no hacen E/S."""

    deployments: Sequence[Deployment] = ()
    events_by_id: dict[str, Event] = field(default_factory=dict)


class DiagnosisRule(Protocol):
    @property
    def name(self) -> str: ...

    def evaluate(self, incident: Incident, context: DiagnosisContext) -> Hypothesis | None: ...
