"""Detectores estadisticos que comparan los eventos de la ventana entre si.

Funciones puras, sin estado ni E/S, igual que el detector por umbral (RF-07, ADR 0006).
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from sentinelops.domain.models import Anomaly, Event, TimeWindow

MAX_EVIDENCE = 20

# Escala la MAD para que sea comparable con la desviacion estandar de una normal.
_MAD_SCALE = 1.4826


def _timed_events_by_service(events: Sequence[Event], window: TimeWindow) -> dict[str, list[Event]]:
    """Agrupa por servicio los eventos de la ventana que traen latencia."""
    by_service: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if window.contains(event.occurred_at) and event.latency_ms is not None:
            by_service[event.service].append(event)
    return by_service


@dataclass(frozen=True, slots=True)
class RobustZScoreDetector:
    """Marca un servicio si algunas latencias se alejan mucho de su mediana (MAD)."""

    z_threshold: float = 3.5
    min_events: int = 10
    # Minimo de latencias atipicas para marcar: 1 sola suele ser ruido (ver nota en detect)
    min_outliers: int = 3
    name: str = "robust_zscore"

    def detect(self, events: Sequence[Event], window: TimeWindow) -> list[Anomaly]:
        by_service = _timed_events_by_service(events, window)
        anomalies: list[Anomaly] = []
        for service in sorted(by_service):
            service_events = by_service[service]
            if len(service_events) < self.min_events:
                continue
            values = [e.latency_ms for e in service_events if e.latency_ms is not None]
            median = statistics.median(values)
            mad = statistics.median([abs(v - median) for v in values])
            if mad == 0:
                continue  # sin dispersion no se pueden medir outliers
            sigma = _MAD_SCALE * mad
            outliers = [
                e
                for e in service_events
                if e.latency_ms is not None and (e.latency_ms - median) / sigma > self.z_threshold
            ]

            # Error (eval S2): un unico outlier por ruido gaussiano creaba un incidente
            # fantasma que, al correlacionar, absorbia el incidente real y desplazaba su
            # inicio - f allaba test_every_labelled_incident_is_detected.
            # Mitigacion:exigir un grupo de outliers (min_outliers), no uno solo.
            if len(outliers) < self.min_outliers:
                continue

            worst = max(values)
            anomalies.append(
                Anomaly(
                    service=service,
                    detector=self.name,
                    signal="latency_robust_z",
                    window=window,
                    score=(worst - median) / sigma,
                    observed=worst,
                    expected=median,
                    evidence_ids=tuple(e.event_id for e in outliers[:MAX_EVIDENCE]),
                )
            )
        return anomalies


@dataclass(frozen=True, slots=True)
class EwmaDetector:
    """Marca un servicio si el nivel suavizado de latencia sube sobre la primera mitad."""

    alpha: float = 0.3
    factor: float = 2.0
    min_events: int = 10
    name: str = "ewma"

    def detect(self, events: Sequence[Event], window: TimeWindow) -> list[Anomaly]:
        by_service = _timed_events_by_service(events, window)
        anomalies: list[Anomaly] = []
        for service in sorted(by_service):
            service_events = sorted(by_service[service], key=lambda e: (e.occurred_at, e.event_id))
            if len(service_events) < self.min_events:
                continue
            values = [e.latency_ms for e in service_events if e.latency_ms is not None]
            half = len(values) // 2
            baseline = statistics.mean(values[:half])
            if baseline <= 0:
                continue
            ewma = baseline
            for value in values[half:]:
                ewma = self.alpha * value + (1 - self.alpha) * ewma
            if ewma < self.factor * baseline:
                continue
            slowest = sorted(service_events[half:], key=lambda e: e.latency_ms or 0.0, reverse=True)
            anomalies.append(
                Anomaly(
                    service=service,
                    detector=self.name,
                    signal="latency_ewma",
                    window=window,
                    score=ewma / baseline,
                    observed=ewma,
                    expected=baseline,
                    evidence_ids=tuple(e.event_id for e in slowest[:MAX_EVIDENCE]),
                )
            )
        return anomalies
