"""Detector por umbrales configurables sobre una ventana temporal (RF-06).

Funcion pura: no hace E/S y siempre devuelve lo mismo para la misma entrada.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

# Para evitar dependencias circulares, importamos solo lo que necesitamos de domain.models
from sentinelops.domain.models import Anomaly, Event, TimeWindow

MAX_EVIDENCE = 20


def p95(values: Sequence[float]) -> float:
    """Percentil 95 por el método nearest-rank (determinista y fácil de explicar)."""
    if not values:
        raise ValueError("p95 de una lista vacía")
    ordered = sorted(values)
    rank = math.ceil(0.95 * len(ordered))
    return ordered[rank - 1]


@dataclass(frozen=True, slots=True)
class ThresholdDetector:
    error_rate_threshold: float = 0.2
    latency_p95_threshold_ms: float = 1000.0
    min_events: int = 10
    name: str = "threshold"

    def detect(self, events: Sequence[Event], window: TimeWindow) -> list[Anomaly]:
        by_service: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            if window.contains(event.occurred_at):
                by_service[event.service].append(event)

        anomalies: list[Anomaly] = []
        for service in sorted(by_service):
            service_events = by_service[service]
            if len(service_events) < self.min_events:
                continue  # muy pocos datos: no se concluye nada
            anomalies.extend(self._error_rate(service, service_events, window))
            anomalies.extend(self._latency(service, service_events, window))
        return anomalies

    def _error_rate(self, service: str, events: list[Event], window: TimeWindow) -> list[Anomaly]:
        errors = [e for e in events if e.is_error]
        rate = len(errors) / len(events)
        if rate <= self.error_rate_threshold:
            return []
        return [
            Anomaly(
                service=service,
                detector=self.name,
                signal="error_rate",
                window=window,
                score=rate / self.error_rate_threshold,
                observed=rate,
                expected=self.error_rate_threshold,
                evidence_ids=tuple(e.event_id for e in errors[:MAX_EVIDENCE]),
            )
        ]

    def _latency(self, service: str, events: list[Event], window: TimeWindow) -> list[Anomaly]:
        timed = [e for e in events if e.latency_ms is not None]
        if len(timed) < self.min_events:
            return []
        observed = p95([e.latency_ms for e in timed if e.latency_ms is not None])
        if observed <= self.latency_p95_threshold_ms:
            return []
        slowest = sorted(timed, key=lambda e: e.latency_ms or 0.0, reverse=True)
        return [
            Anomaly(
                service=service,
                detector=self.name,
                signal="latency_p95_ms",
                window=window,
                score=observed / self.latency_p95_threshold_ms,
                observed=observed,
                expected=self.latency_p95_threshold_ms,
                evidence_ids=tuple(e.event_id for e in slowest[:MAX_EVIDENCE]),
            )
        ]
