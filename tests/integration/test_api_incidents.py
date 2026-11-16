"""API de incidentes: detalle, lista con paginacion y cambio de estado (RF-11, RF-12)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import httpx

from sentinelops.api.auth import generate_api_key, hash_api_key
from sentinelops.persistence.models import HypothesisRow, IncidentRow
from sentinelops.persistence.repositories import SqlApiKeyRepository
from tests.integration.conftest import Keys

URL = "/api/v1/incidents"


async def _key(app: object, scopes: list[str]) -> str:
    raw = generate_api_key()
    async with app.state.sessionmaker() as session:  # type: ignore[attr-defined]
        await SqlApiKeyRepository(session).create("t", hash_api_key(raw), scopes)
    return raw


async def _seed_incident(
    app: object, *, status: str = "open", service: str = "checkout", minute: int = 0
) -> uuid.UUID:
    incident_id = uuid.uuid4()
    # Fecha naive y con microsegundos en 0: evita lios de zona horaria en SQLite.

    created = datetime(2026, 10, 1, 10, 0) + timedelta(minutes=minute)  # noqa: DTZ001
    async with app.state.sessionmaker() as session:  # type: ignore[attr-defined]
        session.add(
            IncidentRow(
                id=incident_id,
                title=service,
                status=status,
                services=[service],
                started_at=created,
                created_at=created,
            )
        )
        session.add(
            HypothesisRow(
                incident_id=incident_id,
                cause="Despliegue reciente",
                confidence=0.86,
                evidence=["deployment:checkout:v2.4.1"],
                rule="recent_deployment",
                recommendation="revertir",
            )
        )
        await session.commit()
    return incident_id


async def test_get_detail_with_hypotheses(client: httpx.AsyncClient, keys: Keys) -> None:
    incident_id = await _seed_incident(client.app)  # type: ignore[attr-defined]
    resp = await client.get(f"{URL}/{incident_id}", headers={"X-API-Key": keys.reader})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "open"
    assert data["services"] == ["checkout"]
    assert data["hypotheses"][0]["rule"] == "recent_deployment"


async def test_get_missing_is_404(client: httpx.AsyncClient, keys: Keys) -> None:
    resp = await client.get(f"{URL}/{uuid.uuid4()}", headers={"X-API-Key": keys.reader})
    assert resp.status_code == 404


async def test_read_requires_scope(client: httpx.AsyncClient, keys: Keys) -> None:
    resp = await client.get(URL, headers={"X-API-Key": keys.writer})  # sin incidents:read
    assert resp.status_code == 403


async def test_list_paginates_by_cursor(client: httpx.AsyncClient, keys: Keys) -> None:
    app = client.app  # type: ignore[attr-defined]
    for i in range(3):
        await _seed_incident(app, minute=i)
    headers = {"X-API-Key": keys.reader}

    first = (await client.get(URL, params={"limit": 2}, headers=headers)).json()
    assert len(first["items"]) == 2
    assert first["next_cursor"] is not None

    second = (
        await client.get(URL, params={"limit": 2, "cursor": first["next_cursor"]}, headers=headers)
    ).json()
    assert len(second["items"]) == 1
    assert second["next_cursor"] is None


async def test_list_filters_by_status(client: httpx.AsyncClient, keys: Keys) -> None:
    app = client.app  # type: ignore[attr-defined]
    await _seed_incident(app, status="open", minute=0)
    await _seed_incident(app, status="resolved", minute=1)
    resp = await client.get(URL, params={"status": "resolved"}, headers={"X-API-Key": keys.reader})
    body = resp.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["status"] == "resolved"


async def test_patch_valid_transition(client: httpx.AsyncClient) -> None:
    app = client.app  # type: ignore[attr-defined]
    incident_id = await _seed_incident(app, status="open")
    writer = await _key(app, ["incidents:write"])
    resp = await client.patch(
        f"{URL}/{incident_id}", json={"status": "investigating"}, headers={"X-API-Key": writer}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"


async def test_patch_invalid_transition_is_409(client: httpx.AsyncClient) -> None:
    app = client.app  # type: ignore[attr-defined]
    incident_id = await _seed_incident(app, status="investigating")
    writer = await _key(app, ["incidents:write"])
    # investigating -> open no esta permitido -> 409.
    resp = await client.patch(
        f"{URL}/{incident_id}", json={"status": "open"}, headers={"X-API-Key": writer}
    )
    assert resp.status_code == 409
