"""El worker procesa ventanas y al reiniciar no duplica anomalias (RF-17, RNF-08)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.application.analyze import Pipeline
from sentinelops.detection.threshold import ThresholdDetector
from sentinelops.diagnosis.rules import ErrorSpikeRule
from sentinelops.domain.models import Event, EventKind, Severity
from sentinelops.persistence.database import build_engine, build_sessionmaker, create_schema
from sentinelops.persistence.models import AnomalyRow, CheckpointRow, HypothesisRow, IncidentRow
from sentinelops.persistence.repositories import SqlEventRepository
from sentinelops.worker import analyze_pending

T0 = datetime(2026, 10, 1, 10, 0, tzinfo=UTC)


@pytest.fixture
async def session(tmp_path: object) -> AsyncIterator[AsyncSession]:
    # SQLite en archivo (no en memoria) para que varias conexiones vean el mismo esquema.
    engine = build_engine(f"sqlite+aiosqlite:///{tmp_path}/worker.db")
    await create_schema(engine)
    async with build_sessionmaker(engine)() as s:
        yield s
    await engine.dispose()


def _error_events(n: int, minute: int) -> list[Event]:
    base = T0 + timedelta(minutes=minute)
    return [
        Event(
            event_id=f"checkout-{minute:02d}-{i:03d}",
            service="checkout",
            kind=EventKind.HTTP_ERROR,
            severity=Severity.ERROR,
            occurred_at=base + timedelta(seconds=i),
            attributes={"http.status_code": 503},
        )
        for i in range(n)
    ]


async def _count_anomalies(session: AsyncSession) -> int:
    return await session.scalar(select(func.count()).select_from(AnomalyRow)) or 0


async def test_worker_processes_and_is_idempotent_on_restart(session: AsyncSession) -> None:
    # Un minuto completo con 100% de error -> el umbral debe marcar una anomalia.
    events = _error_events(15, minute=0) + _error_events(15, minute=1)
    await SqlEventRepository(session).add_many(events)
    # Sin reglas: aqui solo nos interesa que detecte y no duplique al reiniciar.
    pipeline = Pipeline(detectors=[ThresholdDetector()], rules=[])

    processed = await analyze_pending(session, pipeline, window_seconds=60)
    assert processed >= 1
    first_count = await _count_anomalies(session)
    assert first_count >= 1

    # Reinicio normal: el checkpoint evita reprocesar -> 0 ventanas nuevas, mismas anomalias.
    assert await analyze_pending(session, pipeline, window_seconds=60) == 0
    assert await _count_anomalies(session) == first_count

    # El checkpoint quedo guardado.
    checkpoint = await session.get(CheckpointRow, "default")
    assert checkpoint is not None

    # Idempotencia dura: si se reprocesa la misma ventana (checkpoint perdido),
    # ON CONFLICT por la clave de anomalia evita duplicar (RNF-08).
    await session.delete(checkpoint)
    await session.commit()
    await analyze_pending(session, pipeline, window_seconds=60)
    assert await _count_anomalies(session) == first_count


async def test_worker_persists_incident_with_hypothesis(session: AsyncSession) -> None:
    # Una ventana completa con errores 503 -> anomalia por umbral -> incidente persistido.
    events = _error_events(15, minute=0) + _error_events(15, minute=1)
    await SqlEventRepository(session).add_many(events)
    # Con la regla error_spike esperamos ademas una hipotesis (el 503 domina los errores).
    pipeline = Pipeline(detectors=[ThresholdDetector()], rules=[ErrorSpikeRule()])

    await analyze_pending(session, pipeline, window_seconds=60)

    incidents = list((await session.scalars(select(IncidentRow))).all())
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident.status == "open"
    assert incident.services == ["checkout"]

    # La anomalia quedo enlazada a su incidente (incident_id no nulo).
    linked = await session.scalar(
        select(func.count()).select_from(AnomalyRow).where(AnomalyRow.incident_id == incident.id)
    )
    assert linked and linked >= 1

    # La regla error_spike dejo una hipotesis con evidencias concretas (RF-10).
    hypotheses = list(
        (
            await session.scalars(
                select(HypothesisRow).where(HypothesisRow.incident_id == incident.id)
            )
        ).all()
    )
    assert len(hypotheses) == 1
    assert hypotheses[0].rule == "error_spike"
    assert hypotheses[0].evidence
