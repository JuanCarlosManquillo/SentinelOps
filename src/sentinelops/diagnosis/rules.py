"""Reglas de diagnóstico deterministas (RF-10).

Cada regla devuelve una hipótesis con evidencias concretas o `None`.
Nunca se inventa una causa sin eventos que la respalden.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta

from sentinelops.domain.models import Confidence, Hypothesis, Incident
from sentinelops.domain.ports import DiagnosisContext, DiagnosisRule

_HTTP_CAUSES: dict[int, str] = {
    500: "Error interno de la aplicación (500)",
    502: "Una dependencia aguas abajo devuelve respuestas inválidas (502)",
    503: "Servicio o dependencia no disponible (503)",
    504: "Tiempo de espera agotado con una dependencia (504)",
}


@dataclass(frozen=True, slots=True)
class RecentDeploymentRule:
    """Un despliegue del servicio afectado poco antes del incidente es sospechoso."""

    lookback: timedelta = timedelta(minutes=30)
    name: str = "recent_deployment"

    def evaluate(self, incident: Incident, context: DiagnosisContext) -> Hypothesis | None:
        start = incident.started_at
        candidates = [
            d
            for d in context.deployments
            if d.service in incident.services and start - self.lookback <= d.deployed_at <= start
        ]
        if not candidates:
            return None
        latest = max(candidates, key=lambda d: d.deployed_at)
        minutes = (start - latest.deployed_at).total_seconds() / 60
        # Cuanto más cerca del inicio, más confianza (entre 0.5 y 0.9).
        confidence = 0.9 - 0.4 * (minutes / (self.lookback.total_seconds() / 60))
        return Hypothesis(
            cause=(
                f"Despliegue {latest.version} de {latest.service} "
                f"{minutes:.0f} min antes del inicio del incidente"
            ),
            confidence=Confidence(round(confidence, 2)),
            evidence=(f"deployment:{latest.service}:{latest.version}", *incident.evidence_ids[:5]),
            rule=self.name,
            recommendation=f"Comparar {latest.version} con la versión anterior o revertir.",
        )


@dataclass(frozen=True, slots=True)
class ErrorSpikeRule:
    """Si un código HTTP domina los errores, apunta a esa clase de fallo."""

    min_share: float = 0.6
    name: str = "error_spike"

    def evaluate(self, incident: Incident, context: DiagnosisContext) -> Hypothesis | None:
        statuses = [
            (event_id, event.http_status)
            for event_id in incident.evidence_ids
            if (event := context.events_by_id.get(event_id)) and event.http_status
        ]
        if not statuses:
            return None
        code, count = Counter(status for _, status in statuses).most_common(1)[0]
        share = count / len(statuses)
        if code < 500 or share < self.min_share:
            return None
        return Hypothesis(
            cause=_HTTP_CAUSES.get(code, f"Pico de respuestas HTTP {code}"),
            confidence=Confidence(round(0.4 + 0.3 * share, 2)),
            evidence=tuple(eid for eid, status in statuses if status == code)[:10],
            rule=self.name,
            recommendation="Revisar la salud de las dependencias y los logs de esas peticiones.",
        )


def diagnose(
    incident: Incident, context: DiagnosisContext, rules: Sequence[DiagnosisRule]
) -> Incident:
    hypotheses = tuple(h for rule in rules if (h := rule.evaluate(incident, context)))
    return incident.with_hypotheses(hypotheses)
