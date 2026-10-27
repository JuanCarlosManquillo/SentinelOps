"""POST /api/v1/events — ingesta de lotes (RF-01..RF-03).

El router solo traduce HTTP ↔ caso de uso; la lógica vive en `application.ingest`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.api.auth import Principal, require_scope
from sentinelops.api.dependencies import get_session, get_settings_dep
from sentinelops.api.schemas import EventBatchIn, IngestOut
from sentinelops.application.ingest import IngestPolicy, ingest_events
from sentinelops.config import Settings
from sentinelops.persistence.repositories import SqlEventRepository

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestOut,
    description=(
        "Recibe hasta 500 eventos y los guarda sin duplicar (reenviar el mismo event_id "
        "no crea filas). Responde 202 porque el analisis corre despues, en el worker. "
        "Requiere el scope events:write."
    ),
    responses={
        202: {"description": "Lote aceptado. Devuelve received, inserted y duplicates."},
        401: {"description": "Falta la API key o es invalida."},
        403: {"description": "La API key no tiene el scope events:write."},
        413: {"description": "El cuerpo supera el limite permitido."},
        422: {"description": "Esquema invalido o fecha fuera de rango."},
    },
)
async def post_events(
    batch: EventBatchIn,
    principal: Annotated[Principal, Depends(require_scope("events:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> IngestOut:
    if len(batch.events) > settings.max_batch_events:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"máximo {settings.max_batch_events} eventos por lote",
        )
    policy = IngestPolicy(
        max_future_skew=timedelta(seconds=settings.max_future_skew_seconds),
        max_age=timedelta(days=settings.max_event_age_days),
    )
    result = await ingest_events(
        [e.to_domain() for e in batch.events],
        SqlEventRepository(session, api_key_id=principal.key_id),
        now=datetime.now(UTC),
        policy=policy,
    )
    return IngestOut(
        received=result.received, inserted=result.inserted, duplicates=result.duplicates
    )
