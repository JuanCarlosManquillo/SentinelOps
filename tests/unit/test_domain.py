from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from sentinelops.domain.errors import InvalidTransition, InvalidValue
from sentinelops.domain.models import (
    Confidence,
    Hypothesis,
    Incident,
    IncidentStatus,
    Severity,
    TimeWindow,
)
from tests.factories import T0, make_anomaly


class TestTimeWindow:
    def test_rejects_naive_datetimes(self) -> None:
        naive = datetime(2026, 1, 1)  # noqa: DTZ001
        with pytest.raises(InvalidValue):
            TimeWindow(naive, naive + timedelta(minutes=1))

    def test_rejects_inverted_window(self) -> None:
        with pytest.raises(InvalidValue):
            TimeWindow(T0, T0)

    def test_is_half_open(self) -> None:
        window = TimeWindow.starting_at(T0, 60)
        assert window.contains(T0)
        assert not window.contains(window.end)

    def test_next_is_contiguous(self) -> None:
        window = TimeWindow.starting_at(T0, 60)
        assert window.next().start == window.end


def test_severity_is_ordered_and_parsed() -> None:
    assert Severity.CRITICAL > Severity.ERROR > Severity.INFO
    assert Severity.parse("warning") is Severity.WARNING
    with pytest.raises(InvalidValue):
        Severity.parse("fatal")


def test_confidence_bounds() -> None:
    with pytest.raises(InvalidValue):
        Confidence(1.5)


def test_hypothesis_requires_evidence() -> None:
    with pytest.raises(InvalidValue):
        Hypothesis(cause="x", confidence=Confidence(0.5), evidence=(), rule="r")


class TestIncidentLifecycle:
    def test_valid_transitions(self) -> None:
        incident = Incident.open_from(make_anomaly())
        investigating = incident.transition_to(IncidentStatus.INVESTIGATING)
        resolved = investigating.transition_to(IncidentStatus.RESOLVED)
        assert resolved.status is IncidentStatus.RESOLVED
        assert incident.status is IncidentStatus.OPEN  # inmutable

    def test_invalid_transition_raises(self) -> None:
        incident = Incident.open_from(make_anomaly()).transition_to(IncidentStatus.INVESTIGATING)
        with pytest.raises(InvalidTransition):
            incident.transition_to(IncidentStatus.OPEN)

    def test_adding_same_anomaly_is_idempotent(self) -> None:
        anomaly = make_anomaly()
        incident = Incident.open_from(anomaly)
        assert incident.with_anomaly(anomaly) is incident

    def test_hypotheses_sorted_by_confidence(self) -> None:
        low = Hypothesis("a", Confidence(0.3), ("e1",), "r1")
        high = Hypothesis("b", Confidence(0.8), ("e1",), "r2")
        incident = Incident.open_from(make_anomaly()).with_hypotheses((low, high))
        assert [h.cause for h in incident.hypotheses] == ["b", "a"]
