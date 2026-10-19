"""Fixtures de integración.

La base usa SQLite en memoria para que `pytest` funcione sin Docker.
Semana 1: añadir una variante con PostgreSQL real vía testcontainers (marca `postgres`).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
import pytest
from pydantic import SecretStr

from sentinelops.api.app import create_app
from sentinelops.api.auth import generate_api_key, hash_api_key
from sentinelops.config import Settings
from sentinelops.persistence.repositories import SqlApiKeyRepository


@dataclass(frozen=True)
class Keys:
    writer: str
    reader: str


@pytest.fixture
def settings(tmp_path: object) -> Settings:
    return Settings(
        environment="test",
        database_url=SecretStr(f"sqlite+aiosqlite:///{tmp_path}/test.db"),
        auto_create_schema=True,
        max_body_bytes=64_000,
    )


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            c.app = app  # type: ignore[attr-defined]
            yield c


@pytest.fixture
async def keys(client: httpx.AsyncClient) -> Keys:
    app = client.app  # type: ignore[attr-defined]
    writer, reader = generate_api_key(), generate_api_key()
    async with app.state.sessionmaker() as session:
        repo = SqlApiKeyRepository(session)
        await repo.create("writer", hash_api_key(writer), ["events:write"])
        await repo.create("reader", hash_api_key(reader), ["incidents:read"])
    return Keys(writer=writer, reader=reader)
