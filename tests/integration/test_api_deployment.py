"""POST /api/v1/deployments (RF-05): 201 y errores 401/403/422"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from tests.integration.conftest import Keys

URL = "/api/v1/deployments"


def deployment(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "service": "checkout",
        "version": "v2.4.1",
        "deployed_at": datetime.now(UTC).isoformat(),
    }
    body.update(overrides)
    return body


async def test_requires_api_key(client: httpx.AsyncClient) -> None:
    response = await client.post(URL, json=deployment())
    assert response.status_code == 401


async def test_requires_scope(client: httpx.AsyncClient, keys: Keys) -> None:
    response = await client.post(URL, json=deployment(), headers={"X-API-Key": keys.writer})
    assert response.status_code == 403


async def test_creates_deployment(client: httpx.AsyncClient, keys: Keys) -> None:
    response = await client.post(URL, json=deployment(), headers={"X-API-Key": keys.deployment})
    assert response.status_code == 201
    data = response.json()
    assert data["service"] == "checkout"
    assert data["version"] == "v2.4.1"
    assert "id" in data


async def test_rejects_unknown_fields(client: httpx.AsyncClient, keys: Keys) -> None:
    response = await client.post(
        URL, json=deployment(env="prod"), headers={"X-API-Key": keys.deployment}
    )
    assert response.status_code == 422


async def test_rejects_naive_timestamp(client: httpx.AsyncClient, keys: Keys) -> None:
    response = await client.post(
        URL,
        json=deployment(deployed_at="2026-10-17T10:00:00"),
        headers={"X-API-Key": keys.deployment},
    )
    assert response.status_code == 422
