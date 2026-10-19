"""Composición de dependencias: el único lugar que conoce las implementaciones concretas."""

from __future__ import annotations

from datetime import timedelta

from sentinelops.application.analyze import Pipeline
from sentinelops.config import Settings
from sentinelops.detection.threshold import ThresholdDetector
from sentinelops.diagnosis.rules import ErrorSpikeRule, RecentDeploymentRule


def build_pipeline(settings: Settings) -> Pipeline:
    return Pipeline(
        detectors=[
            ThresholdDetector(
                error_rate_threshold=settings.error_rate_threshold,
                latency_p95_threshold_ms=settings.latency_p95_threshold_ms,
                min_events=settings.min_events_per_window,
            ),
            # Semana 2: RobustZScoreDetector(), EwmaDetector()
        ],
        rules=[
            RecentDeploymentRule(lookback=timedelta(seconds=settings.deployment_lookback_seconds)),
            ErrorSpikeRule(),
            # Semana 3: DependencyDownRule(), SaturationRule()
        ],
        correlation_gap=timedelta(seconds=settings.correlation_gap_seconds),
    )
