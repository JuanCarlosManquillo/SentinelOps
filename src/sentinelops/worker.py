"""Worker de análisis por ventanas.

Versión base: `--demo` recorre un dataset sintético en memoria y muestra los incidentes.
Semana 2: bucle sobre PostgreSQL con checkpoint persistente y anomalías idempotentes.
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence

from sentinelops.application.analyze import analyze_window
from sentinelops.bootstrap import build_pipeline
from sentinelops.config import get_settings
from sentinelops.domain.models import Incident, TimeWindow
from sentinelops.ingestion.synthetic import ScenarioConfig, generate

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


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="sentinelops-worker")
    parser.add_argument("--demo", action="store_true", help="analiza un dataset sintético")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.demo:
        _print(run_demo(args.seed))
        return
    raise SystemExit("El modo continuo sobre PostgreSQL llega en la semana 2. Usa --demo.")


if __name__ == "__main__":
    main()
