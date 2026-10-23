"""Humo de integracion contra PostgreSQL 16 real (testcontainers).

Repite el flujo de ingesta sobre Postgres en vez de SQLite, para cerrar diferencias
entre motores (JSONB, ON CONFLICT) que si no solo saldrian en produccion.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from sentinelops.config import Settings
from tests.integration.conftest import Keys

pytestmark = pytest.mark.postgres

URL = "/api/v1/events"


@pytest.fixture
def settings(postgres_container: Any) -> Settings:
    return Settings(
        environment="test",
        database_url=SecretStr(postgres_container.get_connection_url()),
        auto_create_schema=True,
        max_body_bytes=64_000,
    )


async def test_ingest_persists_in_real_postgres(client: httpx.AsyncClient, keys: Keys) -> None:
    payload = {
        "events": [
            {
                "event_id": "checkout-00001",
                "service": "checkout",
                "kind": "http_error",
                "severity": "error",
                "occurred_at": datetime.now(UTC).isoformat(),
                "attributes": {"http.status_code": 503, "latency_ms": 1840},
            }
        ]
    }
    headers = {"X-API-Key": keys.writer}
    first = await client.post(URL, json=payload, headers=headers)
    second = await client.post(URL, json=payload, headers=headers)
    assert first.status_code == 202
    assert first.json() == {"received": 1, "inserted": 1, "duplicates": 0}
    assert second.json() == {"received": 1, "inserted": 0, "duplicates": 1}
