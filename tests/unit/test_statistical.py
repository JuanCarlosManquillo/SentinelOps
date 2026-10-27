from __future__ import annotations

from sentinelops.detection.statistical import EwmaDetector, RobustZScoreDetector
from sentinelops.domain.models import TimeWindow
from tests.factories import T0, make_event

WINDOW = TimeWindow.starting_at(T0, 60)


def test_flags_latency_outliers() -> None:
    normal = [make_event(i, latency=100.0 + i) for i in range(20)]  # 100..119 ms
    slow = [make_event(100 + i, latency=5000.0) for i in range(3)]
    [anomaly] = RobustZScoreDetector().detect(normal + slow, WINDOW)
    assert anomaly.signal == "latency_robust_z"
    assert set(anomaly.evidence_ids) == {e.event_id for e in slow}


def test_no_anomaly_without_outliers() -> None:
    events = [make_event(i, latency=100.0 + i) for i in range(20)]  # subida suave, sin saltos
    assert RobustZScoreDetector().detect(events, WINDOW) == []


def test_ignores_constant_latency() -> None:
    events = [make_event(i, latency=100.0) for i in range(20)]  # MAD = 0, no concluye
    assert RobustZScoreDetector().detect(events, WINDOW) == []


def test_requires_minimum_events() -> None:
    events = [make_event(i, latency=5000.0) for i in range(5)]  # muy pocos datos
    assert RobustZScoreDetector().detect(events, WINDOW) == []


def test_ewma_flags_rising_latency() -> None:
    low = [make_event(i, latency=100.0) for i in range(10)]  # primera mitad: 100 ms
    high = [make_event(100 + i, latency=500.0) for i in range(10)]  # segunda mitad: 500 ms
    [anomaly] = EwmaDetector().detect(low + high, WINDOW)
    assert anomaly.signal == "latency_ewma"
    assert anomaly.observed > anomaly.expected


def test_ewma_no_anomaly_when_stable() -> None:
    events = [make_event(i, latency=100.0) for i in range(20)]  # nivel plano
    assert EwmaDetector().detect(events, WINDOW) == []


def test_ewma_requires_minimum_events() -> None:
    events = [make_event(i, latency=5000.0) for i in range(5)]  # muy pocos datos
    assert EwmaDetector().detect(events, WINDOW) == []
