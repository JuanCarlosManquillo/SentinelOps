"""Revocar una API key la inhabilita de inmediato (RF-15)"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from sentinelops.api.auth import generate_api_key, hash_api_key
from sentinelops.persistence.repositories import SqlApiKeyRepository


async def test_revoked_key_is_rejected(client: httpx.AsyncClient) -> None:
    raw = generate_api_key()
    app = client.app  # type: ignore[attr-defined]
    async with app.state.sessionmaker() as session:
        row = await SqlApiKeyRepository(session).create("temp", hash_api_key(raw), ["events:write"])

    headers = {"X-API-Key": raw}
    payload = {
        "events": [
            {
                "event_id": "temp-1",
                "service": "checkout",
                "kind": "http_error",
                "severity": "error",
                "occurred_at": datetime.now(UTC).isoformat(),
                "attributes": {"http.status_code": 503},
            }
        ]
    }

    # Antes de revocar: la clave funciona (202).
    before = await client.post("/api/v1/events", json=payload, headers=headers)
    assert before.status_code == 202

    # Revocamos.
    async with app.state.sessionmaker() as session:
        await SqlApiKeyRepository(session).revoke(row.id, datetime.now(UTC))

    # Después: la MISMA clave ya no autentica (401).
    after = await client.post("/api/v1/events", json=payload, headers=headers)
    assert after.status_code == 401
