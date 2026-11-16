"""Adaptadores de los puertos de dominio sobre SQLAlchemy."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import delete, func, select, tuple_, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.domain.models import (
    Anomaly,
    Deployment,
    Event,
    EventKind,
    Incident,
    IncidentStatus,
    Severity,
    TimeWindow,
    validate_transition,
)
from sentinelops.persistence.models import (
    AnomalyRow,
    ApiKeyRow,
    CheckpointRow,
    DeploymentRow,
    EventRow,
    HypothesisRow,
    IncidentRow,
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


def _utc(value: datetime) -> datetime:
    # Igual que _as_utc pero para columnas NOT NULL: nunca recibe None.
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _anomaly_to_domain(row: AnomalyRow) -> Anomaly:
    # Reconstruye la anomalia de dominio desde su fila para recorrelacionar en el worker.
    return Anomaly(
        service=row.service,
        detector=row.detector,
        signal=row.signal,
        window=TimeWindow(_utc(row.window_start), _utc(row.window_end)),
        score=row.score,
        observed=row.observed,
        expected=row.expected,
        evidence_ids=tuple(row.evidence_event_ids),
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

    async def list_all(self) -> list[Deployment]:
        # El diagnostico necesita los despliegues para la regla de "despliegue reciente".
        stmt = select(DeploymentRow).order_by(DeploymentRow.deployed_at)
        rows = (await self._session.scalars(stmt)).all()
        return [
            Deployment(service=r.service, version=r.version, deployed_at=_utc(r.deployed_at))
            for r in rows
        ]


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


class SqlIncidentRepository:
    """Lectura y gestion de incidentes para la API (RF-11, RF-12)."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, incident_id: uuid.UUID) -> IncidentRow | None:
        return await self._session.get(IncidentRow, incident_id)

    async def hypotheses_for(self, incident_id: uuid.UUID) -> list[HypothesisRow]:
        stmt = (
            select(HypothesisRow)
            .where(HypothesisRow.incident_id == incident_id)
            .order_by(HypothesisRow.confidence.desc())
        )
        return list((await self._session.scalars(stmt)).all())

    async def list(
        self,
        *,
        status: str | None,
        limit: int,
        cursor: tuple[datetime, uuid.UUID] | None,
    ) -> list[IncidentRow]:
        # Orden estable: del mas reciente al mas antiguo (asi los nuevos no desplazan paginas).
        stmt = select(IncidentRow).order_by(IncidentRow.created_at.desc(), IncidentRow.id.desc())
        if status is not None:
            stmt = stmt.where(IncidentRow.status == status)
        if cursor is not None:
            created, ident = cursor
            # Keyset: trae lo que va "despues" del ultimo visto (comparacion por par).
            stmt = stmt.where(
                tuple_(IncidentRow.created_at, IncidentRow.id) < tuple_(created, ident)
            )
        # Pedimos uno de mas para saber si hay pagina siguiente.
        rows = (await self._session.scalars(stmt.limit(limit + 1))).all()
        return list(rows)

    async def update_status(self, incident_id: uuid.UUID, target: str) -> IncidentRow | None:
        row = await self._session.get(IncidentRow, incident_id)
        if row is None:
            return None
        current = IncidentStatus(row.status)
        new_status = IncidentStatus(target)
        validate_transition(current, new_status)  # si no es valida -> InvalidTransition (409)
        row.status = new_status.value
        if new_status is IncidentStatus.RESOLVED:
            row.ended_at = datetime.now(UTC)  # al resolver, marcamos el fin
        elif current is IncidentStatus.RESOLVED:
            row.ended_at = None  # reapertura: ya no tiene fin
        await self._session.commit()
        return row

    async def load_open(self) -> Sequence[Incident]:
        """Reconstruye como dominio los incidentes no resueltos para que el worker los
        extienda en vez de crear duplicados al reprocesar una ventana (RF-08, RNF-08)."""
        stmt = select(IncidentRow).where(IncidentRow.status != IncidentStatus.RESOLVED.value)
        incidents: list[Incident] = []
        for row in (await self._session.scalars(stmt)).all():
            anomalies = await self._anomalies_of(row.id)
            if not anomalies:
                continue  # sin anomalias no podriamos calcular su inicio; lo omitimos
            # Las hipotesis se recalculan al diagnosticar: no hace falta cargarlas.
            incidents.append(
                Incident(
                    id=row.id,
                    status=IncidentStatus(row.status),
                    anomalies=tuple(anomalies),
                )
            )
        return incidents

    async def _anomalies_of(self, incident_id: uuid.UUID) -> Sequence[Anomaly]:
        stmt = select(AnomalyRow).where(AnomalyRow.incident_id == incident_id)
        return [_anomaly_to_domain(r) for r in (await self._session.scalars(stmt)).all()]

    async def save(self, incidents: Sequence[Incident]) -> None:
        """Persiste incidentes correlacionados: upsert de la cabecera, enlaza sus
        anomalias por clave y reemplaza sus hipotesis. Sin commit: el worker confirma
        todo junto con el checkpoint (RNF-08)."""
        for incident in incidents:
            await self._upsert_incident(incident)
            await self._link_anomalies(incident)
            await self._replace_hypotheses(incident)

    async def _upsert_incident(self, incident: Incident) -> None:
        services = sorted(incident.services)
        title = ", ".join(services)  # titulo simple: los servicios afectados
        row = await self._session.get(IncidentRow, incident.id)
        if row is None:
            self._session.add(
                IncidentRow(
                    id=incident.id,
                    title=title,
                    status=incident.status.value,
                    services=services,
                    started_at=incident.started_at,
                )
            )
        else:
            # No tocamos el status: pudo cambiarlo la API (open->investigating).
            row.title = title
            row.services = services
            row.started_at = incident.started_at

    async def _link_anomalies(self, incident: Incident) -> None:
        # Marca a que incidente pertenece cada anomalia, localizandola por su clave unica.
        for anomaly in incident.anomalies:
            service, detector, signal, window_start = anomaly.key
            await self._session.execute(
                update(AnomalyRow)
                .where(
                    AnomalyRow.service == service,
                    AnomalyRow.detector == detector,
                    AnomalyRow.signal == signal,
                    AnomalyRow.window_start == window_start,
                )
                .values(incident_id=incident.id)
            )

    async def _replace_hypotheses(self, incident: Incident) -> None:
        # Borramos y reinsertamos: el diagnostico es determinista, asi no se acumulan.
        await self._session.execute(
            delete(HypothesisRow).where(HypothesisRow.incident_id == incident.id)
        )
        for hypothesis in incident.hypotheses:
            self._session.add(
                HypothesisRow(
                    incident_id=incident.id,
                    cause=hypothesis.cause,
                    confidence=hypothesis.confidence.value,
                    evidence=list(hypothesis.evidence),
                    rule=hypothesis.rule,
                    recommendation=hypothesis.recommendation,
                )
            )
