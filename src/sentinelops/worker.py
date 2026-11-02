"""Worker de análisis por ventanas.

Versión base: `--demo` recorre un dataset sintético en memoria y muestra los incidentes.
Semana 2: bucle sobre PostgreSQL con checkpoint persistente y anomalías idempotentes.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.application.analyze import analyze_window
from sentinelops.bootstrap import build_pipeline
from sentinelops.config import get_settings
from sentinelops.domain.models import Incident, TimeWindow
from sentinelops.domain.ports import Detector
from sentinelops.ingestion.synthetic import ScenarioConfig, generate
from sentinelops.persistence.database import build_engine, build_sessionmaker
from sentinelops.persistence.repositories import (
    SqlAnomalyRepository,
    SqlCheckpointRepository,
    SqlEventRepository,
)

logger = logging.getLogger("sentinelops.worker")


def run_demo(seed: int) -> list[Incident]:
    settings = get_settings()
    pipeline = build_pipeline(settings)
    config = ScenarioConfig(seed=seed)
    data = generate(config)
    events_by_id = {e.event_id: e for e in data.events}

    window = TimeWindow.starting_at(config.start, settings.window_seconds)
    end = data.events[-1].occurred_at
    incidents: list[Incident] = []
    cursor = 0
    while window.start <= end:
        batch = []
        while cursor < len(data.events) and data.events[cursor].occurred_at < window.end:
            batch.append(data.events[cursor])
            cursor += 1
        result = analyze_window(pipeline, window, batch, data.deployments, incidents, events_by_id)
        incidents = result.incidents
        window = window.next()
    return incidents


def _print(incidents: Sequence[Incident]) -> None:
    for incident in incidents:
        print(
            f"- {incident.started_at:%H:%M} {','.join(sorted(incident.services))} "
            f"({len(incident.anomalies)} anomalías)"
        )
        for hypothesis in incident.hypotheses:
            print(f"    {hypothesis.confidence.value:.2f}  {hypothesis.cause}")
        if not incident.hypotheses:
            print("    sin hipótesis: ninguna regla tiene evidencias suficientes")


async def analyze_pending(
    session: AsyncSession,
    detectors: Sequence[Detector],
    window_seconds: int,
    checkpoint_name: str = "default",
) -> int:
    """Procesa las ventanas completas pendientes: detecta y guarda anomalias + checkpoint.

    Idempotente: reprocesar una ventana tras un reinicio no duplica anomalias (RNF-08).
    Devuelve cuantas ventanas proceso.
    """
    events = SqlEventRepository(session)
    anomalies_repo = SqlAnomalyRepository(session)
    checkpoint = SqlCheckpointRepository(session)

    # Retoma desde el checkpoint; si no hay, desde el evento mas antiguo.
    start = await checkpoint.get(checkpoint_name)
    if start is None:
        start = await events.earliest_occurred_at()
    latest = await events.latest_occurred_at()
    if start is None or latest is None:
        return 0  # no hay eventos todavia

    processed = 0
    window = TimeWindow.starting_at(start, window_seconds)
    while window.end <= latest:  # solo ventanas ya completas
        window_events = await events.list_window(window)
        found = [a for d in detectors for a in d.detect(window_events, window)]
        await anomalies_repo.add_many(found)
        await checkpoint.set(checkpoint_name, window.end)
        await session.commit()  # anomalias y checkpoint en la misma transaccion
        processed += 1
        window = window.next()
    return processed


async def _run_continuous() -> None:
    """Bucle infinito: analiza las ventanas completas pendientes cada `window_seconds`"""
    settings = get_settings()
    detectors = build_pipeline(settings).detectors
    engine = build_engine(settings.database_url.get_secret_value())
    sessionmaker = build_sessionmaker(engine)
    logger.info("worker iniciado; ventanas de %d s", settings.window_seconds)
    try:
        while True:
            async with sessionmaker() as session:
                processed = await analyze_pending(session, detectors, settings.window_seconds)
            if processed:
                logger.info("procesadas %d ventanas", processed)
            await asyncio.sleep(settings.window_seconds)
    finally:
        await engine.dispose()


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="sentinelops-worker")
    parser.add_argument("--demo", action="store_true", help="analiza un dataset sintético")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.demo:
        _print(run_demo(args.seed))
        return
    raise SystemExit(_run_continuous())


if __name__ == "__main__":
    main()
