from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from tests.integration.conftest import Keys

URL = "/api/v1/events"


def event(n: int = 1, **overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "event_id": f"checkout-{n:05d}",
        "service": "checkout",
        "kind": "http_error",
        "severity": "error",
        "occurred_at": datetime.now(UTC).isoformat(),
        "message": "POST /pay returned 503",
        "attributes": {"http.status_code": 503, "latency_ms": 1840},
    }
    body.update(overrides)
    return body


async def test_health_is_public(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["database"] == "ok"
    assert response.headers["x-content-type-options"] == "nosniff"


async def test_requires_api_key(client: httpx.AsyncClient) -> None:
    response = await client.post(URL, json={"events": [event()]})
    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"


async def test_rejects_unknown_key(client: httpx.AsyncClient, keys: Keys) -> None:
    headers = {"X-API-Key": "so_" + "x" * 43}
    assert (await client.post(URL, json={"events": [event()]}, headers=headers)).status_code == 401


async def test_requires_scope(client: httpx.AsyncClient, keys: Keys) -> None:
    response = await client.post(
        URL, json={"events": [event()]}, headers={"X-API-Key": keys.reader}
    )
    assert response.status_code == 403


async def test_accepts_batch_and_is_idempotent(client: httpx.AsyncClient, keys: Keys) -> None:
    headers = {"X-API-Key": keys.writer}
    payload = {"events": [event(i) for i in range(3)]}
    first = await client.post(URL, json=payload, headers=headers)
    second = await client.post(URL, json=payload, headers=headers)
    assert first.status_code == 202
    assert first.json() == {"received": 3, "inserted": 3, "duplicates": 0}
    assert second.json() == {"received": 3, "inserted": 0, "duplicates": 3}


async def test_rejects_unknown_fields(client: httpx.AsyncClient, keys: Keys) -> None:
    response = await client.post(
        URL, json={"events": [event(is_admin=True)]}, headers={"X-API-Key": keys.writer}
    )
    assert response.status_code == 422


async def test_rejects_naive_timestamp(client: httpx.AsyncClient, keys: Keys) -> None:
    response = await client.post(
        URL,
        json={"events": [event(occurred_at="2026-10-17T10:00:00")]},
        headers={"X-API-Key": keys.writer},
    )
    assert response.status_code == 422


async def test_rejects_future_timestamp(client: httpx.AsyncClient, keys: Keys) -> None:
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    response = await client.post(
        URL, json={"events": [event(occurred_at=future)]}, headers={"X-API-Key": keys.writer}
    )
    assert response.status_code == 422
    assert response.json()["title"] == "Event rejected"


async def test_rejects_oversized_batch(client: httpx.AsyncClient, keys: Keys) -> None:
    payload = {"events": [event(i, message="") for i in range(501)]}
    response = await client.post(URL, json=payload, headers={"X-API-Key": keys.writer})
    assert response.status_code in {413, 422}


async def test_rejects_oversized_body(client: httpx.AsyncClient, keys: Keys) -> None:
    payload = {"events": [event(1, message="x" * 1999)] * 40}  # > 64 KB en tests
    response = await client.post(URL, json=payload, headers={"X-API-Key": keys.writer})
    assert response.status_code == 413


async def test_validation_errors_do_not_echo_input(client: httpx.AsyncClient, keys: Keys) -> None:
    response = await client.post(
        URL,
        json={"events": [event(severity="top-secret-value")]},
        headers={"X-API-Key": keys.writer},
    )
    assert response.status_code == 422
    assert "top-secret-value" not in response.text


async def test_secrets_are_redacted_before_storage(client: httpx.AsyncClient, keys: Keys) -> None:
    from sqlalchemy import select

    from sentinelops.persistence.models import EventRow

    body = event(42, attributes={"authorization": "Bearer abc"}, message="token=abc123")
    await client.post(URL, json={"events": [body]}, headers={"X-API-Key": keys.writer})
    app = client.app  # type: ignore[attr-defined]
    async with app.state.sessionmaker() as session:
        row = (await session.scalars(select(EventRow))).one()
    assert row.attributes["authorization"] == "[REDACTED]"
    assert "abc123" not in row.message
