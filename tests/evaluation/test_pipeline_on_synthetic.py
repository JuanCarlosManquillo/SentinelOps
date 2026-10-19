"""Prueba de humo de la evaluación: el pipeline completo sobre el dataset sintético.

No es la evaluación final (semana 4): solo protege que el flujo extremo a extremo
siga detectando los incidentes etiquetados mientras se desarrolla.
"""

from __future__ import annotations

from sentinelops.ingestion.synthetic import ScenarioConfig, generate
from sentinelops.worker import run_demo


def test_every_labelled_incident_is_detected() -> None:
    labels = generate(ScenarioConfig(seed=42)).labels
    incidents = run_demo(seed=42)
    for label in labels:
        matches = [
            i
            for i in incidents
            if label.service in i.services and label.start <= i.started_at < label.end
        ]
        assert matches, f"no se detectó {label.type} en {label.service}"


def test_bad_deployment_top_hypothesis_is_the_deployment() -> None:
    label = next(
        lb for lb in generate(ScenarioConfig(seed=42)).labels if lb.type == "bad_deployment"
    )
    incident = next(
        i for i in run_demo(seed=42) if label.service in i.services and i.started_at >= label.start
    )
    assert incident.hypotheses, "el incidente no tiene hipótesis"
    assert incident.hypotheses[0].evidence[0] == label.root_cause
