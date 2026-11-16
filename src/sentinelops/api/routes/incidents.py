"""GET/PATCH /api/v1/incidents - consultar y gestionar incidentes (RF-11, RF-12)."""

from __future__ import annotations

import base64
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.api.auth import Principal, require_scope
from sentinelops.api.dependencies import get_session
from sentinelops.api.schemas import (
    HypothesisOut,
    IncidentListOut,
    IncidentOut,
    IncidentPatchIn,
    IncidentSummaryOut,
)
from sentinelops.persistence.models import HypothesisRow, IncidentRow
from sentinelops.persistence.repositories import SqlIncidentRepository

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


def _to_out(row: IncidentRow, hypotheses: list[HypothesisRow]) -> IncidentOut:
    return IncidentOut(
        id=row.id,
        status=row.status,
        services=row.services,
        started_at=row.started_at,
        ended_at=row.ended_at,
        hypotheses=[
            HypothesisOut(
                cause=h.cause,
                confidence=h.confidence,
                rule=h.rule,
                recommendation=h.recommendation,
                evidence=h.evidence,
            )
            for h in hypotheses
        ],
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentOut,
    summary="Detalle de un incidente",
    description="Devuelve un incidente con sus hipotesis ordenadas por confianza.",
    responses={401: {}, 403: {}, 404: {"description": "No existe el incidente."}},
)
async def get_incident(
    incident_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require_scope("incidents:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentOut:
    repo = SqlIncidentRepository(session)
    row = await repo.get(incident_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="incidente no encontrado")
    return _to_out(row, await repo.hypotheses_for(incident_id))


def _to_summary(row: IncidentRow) -> IncidentSummaryOut:
    return IncidentSummaryOut(
        id=row.id,
        status=row.status,
        services=row.services,
        started_at=row.started_at,
        ended_at=row.ended_at,
    )


def _encode_cursor(row: IncidentRow) -> str:
    raw = f"{row.created_at.isoformat()}|{row.id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        created_str, id_str = raw.split("|", 1)
        return datetime.fromisoformat(created_str), uuid.UUID(id_str)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "cursor invalido") from exc


@router.patch(
    "/{incident_id}",
    response_model=IncidentOut,
    summary="Cambiar el estado de un incidente",
    description="Transiciones validas: open -> investigating -> resolved y reapertura. "
    "Una transicion no permitida devuelve 409.",
    responses={
        401: {},
        403: {},
        404: {"description": "No existe el incidente."},
        409: {"description": "Transicion de estado no permitida."},
    },
)
async def patch_incident(
    incident_id: uuid.UUID,
    body: IncidentPatchIn,
    principal: Annotated[Principal, Depends(require_scope("incidents:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> IncidentOut:
    repo = SqlIncidentRepository(session)
    row = await repo.update_status(incident_id, body.status)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="incidente no encontrado")
    return _to_out(row, await repo.hypotheses_for(incident_id))


@router.get(
    "",
    response_model=IncidentListOut,
    summary="Listar incidentes",
    description="Lista del mas reciente al mas antiguo, con filtro por estado y "
    "paginacion por cursor (no por offset).",
    responses={401: {}, 403: {}, 422: {}},
)
async def list_incidents(
    principal: Annotated[Principal, Depends(require_scope("incidents:read"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: str | None = None,
) -> IncidentListOut:
    decoded = _decode_cursor(cursor) if cursor else None
    repo = SqlIncidentRepository(session)
    rows = await repo.list(status=status_filter, limit=limit, cursor=decoded)
    # Si vino uno de mas, hay pagina siguiente: el cursor apunta al ultimo de ESTA pagina.
    next_cursor = _encode_cursor(rows[limit - 1]) if len(rows) > limit else None
    return IncidentListOut(items=[_to_summary(r) for r in rows[:limit]], next_cursor=next_cursor)
