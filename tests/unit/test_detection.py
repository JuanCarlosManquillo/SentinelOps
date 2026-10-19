from __future__ import annotations

import pytest

from sentinelops.detection.threshold import ThresholdDetector, p95
from sentinelops.domain.models import TimeWindow
from tests.factories import T0, make_event

WINDOW = TimeWindow.starting_at(T0, 60)


def test_p95_nearest_rank() -> None:
    assert p95([float(v) for v in range(1, 101)]) == 95.0
    with pytest.raises(ValueError):
        p95([])


def test_no_anomaly_below_threshold() -> None:
    events = [make_event(i, status=500 if i < 2 else 200) for i in range(20)]  # 10 %
    assert ThresholdDetector(error_rate_threshold=0.2).detect(events, WINDOW) == []


def test_error_rate_anomaly_carries_evidence() -> None:
    events = [make_event(i, status=503 if i < 10 else 200) for i in range(20)]  # 50 %
    [anomaly] = ThresholdDetector(error_rate_threshold=0.2).detect(events, WINDOW)
    assert anomaly.signal == "error_rate"
    assert anomaly.observed == pytest.approx(0.5)
    assert set(anomaly.evidence_ids) == {e.event_id for e in events[:10]}


def test_latency_anomaly() -> None:
    events = [make_event(i, latency=2000.0) for i in range(20)]
    [anomaly] = ThresholdDetector(latency_p95_threshold_ms=1000).detect(events, WINDOW)
    assert anomaly.signal == "latency_p95_ms"
    assert anomaly.observed == 2000.0


def test_requires_minimum_events() -> None:
    events = [make_event(i, status=500) for i in range(5)]
    assert ThresholdDetector(min_events=10).detect(events, WINDOW) == []


def test_ignores_events_outside_window() -> None:
    outside = WINDOW.next().start
    events = [make_event(i, status=500, at=outside) for i in range(20)]
    assert ThresholdDetector().detect(events, WINDOW) == []


def test_result_does_not_depend_on_input_order() -> None:
    events = [make_event(i, status=500 if i % 2 else 200) for i in range(30)]
    detector = ThresholdDetector()
    forward = detector.detect(events, WINDOW)
    backward = detector.detect(list(reversed(events)), WINDOW)
    assert [(a.signal, a.observed) for a in forward] == [(a.signal, a.observed) for a in backward]
    assert {frozenset(a.evidence_ids) for a in forward} == {
        frozenset(a.evidence_ids) for a in backward
    }
