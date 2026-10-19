from __future__ import annotations

from datetime import timedelta

from sentinelops.correlation.correlator import correlate
from sentinelops.diagnosis.rules import ErrorSpikeRule, RecentDeploymentRule, diagnose
from sentinelops.domain.models import Deployment, IncidentStatus
from sentinelops.domain.ports import DiagnosisContext
from tests.factories import T0, make_anomaly, make_event


class TestCorrelation:
    def test_close_anomalies_same_service_join(self) -> None:
        incidents = correlate([make_anomaly(minute=0), make_anomaly(minute=3)], [])
        assert len(incidents) == 1
        assert len(incidents[0].anomalies) == 2

    def test_distant_anomalies_split(self) -> None:
        incidents = correlate([make_anomaly(minute=0), make_anomaly(minute=30)], [])
        assert len(incidents) == 2

    def test_different_services_split(self) -> None:
        anomalies = [make_anomaly("checkout"), make_anomaly("catalog")]
        assert len(correlate(anomalies, [])) == 2

    def test_resolved_incident_is_not_reopened_by_correlation(self) -> None:
        [first] = correlate([make_anomaly(minute=0)], [])
        resolved = first.transition_to(IncidentStatus.RESOLVED)
        incidents = correlate([make_anomaly(minute=2)], [resolved])
        assert len(incidents) == 2


class TestDiagnosis:
    def test_recent_deployment_rule(self) -> None:
        [incident] = correlate([make_anomaly(minute=0)], [])
        deploy = Deployment("checkout", "v2", T0 - timedelta(minutes=3))
        hypothesis = RecentDeploymentRule().evaluate(incident, DiagnosisContext([deploy]))
        assert hypothesis is not None
        assert "v2" in hypothesis.cause
        assert hypothesis.evidence[0] == "deployment:checkout:v2"
        assert 0.5 <= hypothesis.confidence.value <= 0.9

    def test_old_deployment_is_ignored(self) -> None:
        [incident] = correlate([make_anomaly(minute=0)], [])
        deploy = Deployment("checkout", "v2", T0 - timedelta(hours=2))
        assert RecentDeploymentRule().evaluate(incident, DiagnosisContext([deploy])) is None

    def test_error_spike_rule_uses_dominant_status(self) -> None:
        events = [make_event(i, status=503) for i in range(8)] + [make_event(8, status=500)]
        anomaly = make_anomaly(evidence=tuple(e.event_id for e in events))
        [incident] = correlate([anomaly], [])
        ctx = DiagnosisContext(events_by_id={e.event_id: e for e in events})
        hypothesis = ErrorSpikeRule().evaluate(incident, ctx)
        assert hypothesis is not None
        assert "503" in hypothesis.cause
        assert len(hypothesis.evidence) == 8

    def test_every_hypothesis_points_to_existing_evidence(self) -> None:
        events = [make_event(i, status=503) for i in range(5)]
        anomaly = make_anomaly(evidence=tuple(e.event_id for e in events))
        [incident] = correlate([anomaly], [])
        ctx = DiagnosisContext(
            deployments=[Deployment("checkout", "v9", T0 - timedelta(minutes=1))],
            events_by_id={e.event_id: e for e in events},
        )
        diagnosed = diagnose(incident, ctx, [RecentDeploymentRule(), ErrorSpikeRule()])
        known = set(ctx.events_by_id) | {"deployment:checkout:v9"}
        for hypothesis in diagnosed.hypotheses:
            assert set(hypothesis.evidence) <= known
