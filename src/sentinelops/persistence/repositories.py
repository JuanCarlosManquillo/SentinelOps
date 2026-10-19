"""Adaptadores de los puertos de dominio sobre SQLAlchemy."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.domain.models import Event, EventKind, Severity, TimeWindow
from sentinelops.persistence.models import ApiKeyRow, EventRow


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
