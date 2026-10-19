"""Caso de uso: ingerir un lote de eventos (RF-01, RF-02, RF-03).

Aplica las reglas de negocio de la ingesta que no son de formato (eso lo hace Pydantic):
ventana temporal aceptable y redacción de secretos. No ejecuta detección (RNF-07).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from sentinelops.domain.errors import EventRejected
from sentinelops.domain.models import Event
from sentinelops.domain.ports import EventWriter
from sentinelops.ingestion.redaction import redact_attributes, redact_text


@dataclass(frozen=True, slots=True)
class IngestResult:
    received: int
    inserted: int

    @property
    def duplicates(self) -> int:
        return self.received - self.inserted


@dataclass(frozen=True, slots=True)
class IngestPolicy:
    max_future_skew: timedelta = timedelta(minutes=5)
    max_age: timedelta = timedelta(days=7)


DEFAULT_POLICY = IngestPolicy()


async def ingest_events(
    events: Sequence[Event],
    writer: EventWriter,
    now: datetime,
    policy: IngestPolicy = DEFAULT_POLICY,
) -> IngestResult:
    for event in events:
        if event.occurred_at > now + policy.max_future_skew:
            raise EventRejected(f"{event.event_id}: occurred_at está en el futuro")
        if event.occurred_at < now - policy.max_age:
            raise EventRejected(f"{event.event_id}: occurred_at es demasiado antiguo")

    sanitized = [
        replace(e, message=redact_text(e.message), attributes=redact_attributes(e.attributes))
        for e in events
    ]
    inserted = await writer.add_many(sanitized)
    return IngestResult(received=len(events), inserted=inserted)
