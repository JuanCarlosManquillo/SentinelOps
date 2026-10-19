"""Caso de uso: analizar una ventana (detección → correlación → diagnóstico).

Orquesta funciones puras; el worker se encarga de leer y guardar.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta

from sentinelops.correlation.correlator import correlate
from sentinelops.diagnosis.rules import diagnose
from sentinelops.domain.models import Anomaly, Deployment, Event, Incident, TimeWindow
from sentinelops.domain.ports import Detector, DiagnosisContext, DiagnosisRule


@dataclass(frozen=True, slots=True)
class Pipeline:
    detectors: Sequence[Detector]
    rules: Sequence[DiagnosisRule]
    correlation_gap: timedelta = timedelta(minutes=10)


@dataclass(frozen=True, slots=True)
class WindowAnalysis:
    window: TimeWindow
    anomalies: list[Anomaly]
    incidents: list[Incident]


def analyze_window(
    pipeline: Pipeline,
    window: TimeWindow,
    events: Sequence[Event],
    deployments: Sequence[Deployment],
    open_incidents: Sequence[Incident],
    events_by_id: dict[str, Event] | None = None,
) -> WindowAnalysis:
    anomalies = [a for d in pipeline.detectors for a in d.detect(events, window)]
    if not anomalies:
        return WindowAnalysis(window, [], list(open_incidents))

    incidents = correlate(anomalies, open_incidents, pipeline.correlation_gap)
    lookup = events_by_id if events_by_id is not None else {e.event_id: e for e in events}
    context = DiagnosisContext(deployments=deployments, events_by_id=lookup)
    diagnosed = [diagnose(i, context, pipeline.rules) for i in incidents]
    return WindowAnalysis(window, anomalies, diagnosed)
