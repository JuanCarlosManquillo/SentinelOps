"""Correlación de anomalías en incidentes (RF-08).

Regla v1: una anomalía se une a un incidente abierto del mismo servicio si empieza
a menos de `gap` de la última anomalía del incidente. Si no, abre uno nuevo.
Semana 3: añadir dependencias entre servicios y despliegues.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import timedelta

from sentinelops.domain.models import Anomaly, Incident, IncidentStatus


def correlate(
    anomalies: Iterable[Anomaly],
    open_incidents: Sequence[Incident],
    gap: timedelta = timedelta(minutes=10),
) -> list[Incident]:
    """Devuelve la lista completa de incidentes (los existentes actualizados y los nuevos)."""
    incidents = list(open_incidents)
    for anomaly in sorted(anomalies, key=lambda a: (a.window.start, a.service, a.signal)):
        index = _find_match(incidents, anomaly, gap)
        if index is None:
            incidents.append(Incident.open_from(anomaly))
        else:
            incidents[index] = incidents[index].with_anomaly(anomaly)
    return incidents


def _find_match(incidents: Sequence[Incident], anomaly: Anomaly, gap: timedelta) -> int | None:
    for index, incident in enumerate(incidents):
        if incident.status is IncidentStatus.RESOLVED:
            continue
        same_service = anomaly.service in incident.services
        close_in_time = anomaly.window.start - incident.last_seen_at <= gap
        if same_service and close_in_time:
            return index
    return None
