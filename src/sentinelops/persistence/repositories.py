"""Adaptadores de los puertos de dominio sobre SQLAlchemy."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.domain.models import Anomaly, Deployment, Event, EventKind, Severity, TimeWindow
from sentinelops.persistence.models import (
    AnomalyRow,
    ApiKeyRow,
    CheckpointRow,
    DeploymentRow,
    EventRow,
)


class SqlEventRepository:
    """Implementa `EventWriter` y `EventReader`."""

    def __init__(self, session: AsyncSession, api_key_id: uuid.UUID | None = None) -> None:
        self._session = session
        self._api_key_id = api_key_id

    async def add_many(self, events: Sequence[Event]) -> int:
        if not events:
            return 0
        rows = [
            {
                "id": uuid.uuid4(),
                "event_id": e.event_id,
                "service": e.service,
                "kind": e.kind.value,
                "severity": int(e.severity),
                "occurred_at": e.occurred_at,
                "message": e.message,
                "attributes": dict(e.attributes),
                "trace_id": e.trace_id,
                "api_key_id": self._api_key_id,
            }
            for e in events
        ]
        dialect = self._session.get_bind().dialect.name
        insert = postgresql.insert if dialect == "postgresql" else sqlite.insert
        # Idempotencia (RF-03): reenviar el mismo event_id no crea filas nuevas.
        stmt = (
            insert(EventRow)
            .values(rows)
            .on_conflict_do_nothing(index_elements=["event_id"])
            .returning(EventRow.event_id)
        )
        result = await self._session.execute(stmt)
        inserted = len(result.all())
        await self._session.commit()
        return inserted

    async def list_window(self, window: TimeWindow) -> list[Event]:
        stmt = (
            select(EventRow)
            .where(EventRow.occurred_at >= window.start, EventRow.occurred_at < window.end)
            .order_by(EventRow.occurred_at, EventRow.event_id)
        )
        rows = (await self._session.scalars(stmt)).all()
        return [_to_domain(r) for r in rows]

    # Devuelve la fecha mas antigua de un evento
    async def earliest_occurred_at(self) -> datetime | None:
        stmt = select(func.min(EventRow.occurred_at))
        result: datetime | None = await self._session.scalar(stmt)
        return _as_utc(result)

    # Devuelve la fecha mas reciente de un evento
    async def latest_occurred_at(self) -> datetime | None:
        stmt = select(func.max(EventRow.occurred_at))
        result: datetime | None = await self._session.scalar(stmt)
        return _as_utc(result)


def _to_domain(row: EventRow) -> Event:
    return Event(
        event_id=row.event_id,
        service=row.service,
        kind=EventKind(row.kind),
        severity=Severity(row.severity),
        # SQLite devuelve fechas sin zona; PostgreSQL (timestamptz) ya vienen en UTC.
        occurred_at=row.occurred_at
        if row.occurred_at.tzinfo
        else row.occurred_at.replace(tzinfo=UTC),
        message=row.message,
        attributes=row.attributes,
        trace_id=row.trace_id,
    )


def _as_utc(value: datetime | None) -> datetime | None:
    # SQLite devuelve fechas sin zona; las normalizamos a UTC como en _to_domain
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class SqlApiKeyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def find_active(self, key_hash: str) -> ApiKeyRow | None:
        stmt = select(ApiKeyRow).where(
            ApiKeyRow.key_hash == key_hash, ApiKeyRow.revoked_at.is_(None)
        )
        return (await self._session.scalars(stmt)).first()

    async def create(self, name: str, key_hash: str, scopes: list[str]) -> ApiKeyRow:
        row = ApiKeyRow(name=name, key_hash=key_hash, scopes=scopes)
        self._session.add(row)
        await self._session.commit()
        return row

    async def revoke(self, key_id: uuid.UUID, at: datetime) -> None:
        row = await self._session.get(ApiKeyRow, key_id)
        if row is not None:
            row.revoked_at = at
            await self._session.commit()


class InMemoryEventRepository:
    """Doble de prueba: misma semántica idempotente, sin base de datos."""

    def __init__(self) -> None:
        self.events: dict[str, Event] = {}

    async def add_many(self, events: Sequence[Event]) -> int:
        new = [e for e in events if e.event_id not in self.events]
        self.events.update({e.event_id: e for e in new})
        return len(new)

    async def list_window(self, window: TimeWindow) -> list[Event]:
        found = [e for e in self.events.values() if window.contains(e.occurred_at)]
        return sorted(found, key=lambda e: (e.occurred_at, e.event_id))


class SqlDeploymentRepository:
    """Implementa `DeploymentWriter` y `DeploymentReader`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, deployment: Deployment) -> uuid.UUID:
        row = DeploymentRow(
            service=deployment.service,
            version=deployment.version,
            deployed_at=deployment.deployed_at,
        )
        self._session.add(row)
        await self._session.commit()
        return row.id


class InMemoryDeploymentRepository:
    """Doble de prueba de DeploymentWriter, sin base de datos."""

    def __init__(self) -> None:
        self.deployments: list[Deployment] = []

    async def add(self, deployment: Deployment) -> uuid.UUID:
        self.deployments.append(deployment)
        return uuid.uuid4()


class SqlCheckpointRepository:
    """Guarda y lee la ultima ventana procesada por el worker (RF-17)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, name: str) -> datetime | None:
        row = await self._session.get(CheckpointRow, name)
        return _as_utc(row.window_end) if row else None

    async def set(self, name: str, window_end: datetime) -> None:
        # Sin commit: el worker confirma el checkpoint junto con las anomalias.
        row = await self._session.get(CheckpointRow, name)
        if row is None:
            self._session.add(CheckpointRow(name=name, window_end=window_end))
        else:
            row.window_end = window_end


class SqlAnomalyRepository:
    """Inserta anomalias de forma idempotente por su clave (RNF-08)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_many(self, anomalies: Sequence[Anomaly]) -> int:
        if not anomalies:
            return 0
        rows = [
            {
                "id": uuid.uuid4(),
                "service": a.service,
                "detector": a.detector,
                "signal": a.signal,
                "window_start": a.window.start,
                "window_end": a.window.end,
                "score": a.score,
                "observed": a.observed,
                "expected": a.expected,
                "evidence_event_ids": list(a.evidence_ids),
            }
            for a in anomalies
        ]
        dialect = self._session.get_bind().dialect.name
        insert = postgresql.insert if dialect == "postgresql" else sqlite.insert
        # Reprocesar una ventana tras un reinicio no duplica: ON CONFLICT por la clave.
        stmt = (
            insert(AnomalyRow)
            .values(rows)
            .on_conflict_do_nothing(
                index_elements=["service", "detector", "signal", "window_start"]
            )
            .returning(AnomalyRow.id)
        )
        result = await self._session.execute(stmt)
        return len(result.all())
