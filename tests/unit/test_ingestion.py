from __future__ import annotations

from datetime import timedelta

import pytest

from sentinelops.application.ingest import ingest_events
from sentinelops.domain.errors import EventRejected
from sentinelops.ingestion.redaction import REDACTED, redact_attributes, redact_text
from sentinelops.ingestion.synthetic import ScenarioConfig, generate
from sentinelops.persistence.repositories import InMemoryEventRepository
from tests.factories import T0, make_event


def test_redacts_sensitive_keys() -> None:
    out = redact_attributes({"Authorization": "Bearer abc", "api_key": "x", "route": "/pay"})
    assert out == {"Authorization": REDACTED, "api_key": REDACTED, "route": "/pay"}


def test_redacts_secrets_in_text() -> None:
    text = redact_text("call failed token=abc123 with Bearer eyJhbGci.x.y")
    assert "abc123" not in text and "eyJhbGci" not in text


async def test_ingest_is_idempotent() -> None:
    repo = InMemoryEventRepository()
    events = [make_event(i) for i in range(5)]
    first = await ingest_events(events, repo, now=T0)
    second = await ingest_events(events, repo, now=T0)
    assert (first.inserted, second.inserted, second.duplicates) == (5, 0, 5)


async def test_ingest_redacts_before_persisting() -> None:
    repo = InMemoryEventRepository()
    await ingest_events([make_event(1, password="hunter2")], repo, now=T0)
    stored = next(iter(repo.events.values()))
    assert stored.attributes["password"] == REDACTED


@pytest.mark.parametrize("offset", [timedelta(minutes=10), -timedelta(days=8)])
async def test_ingest_rejects_out_of_range_timestamps(offset: timedelta) -> None:
    with pytest.raises(EventRejected):
        await ingest_events([make_event(1, at=T0 + offset)], InMemoryEventRepository(), now=T0)


def test_synthetic_dataset_is_reproducible() -> None:
    a, b = generate(ScenarioConfig(seed=7)), generate(ScenarioConfig(seed=7))
    assert a.events == b.events and a.labels == b.labels
    assert generate(ScenarioConfig(seed=8)).events != a.events
    assert len({e.event_id for e in a.events}) == len(a.events)
