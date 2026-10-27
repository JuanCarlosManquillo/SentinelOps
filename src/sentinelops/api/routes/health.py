"""GET /health — sin autenticación; no expone detalles internos."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops import __version__
from sentinelops.api.dependencies import get_session
from sentinelops.api.schemas import HealthOut

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthOut,
    summary="Estado del servicio",
    description="Comprueba que la API responde y que la base de datos esta disponible."
    "Devuelve 503 si la base de datos no responde. No requiere autenticación.",
)
async def health(
    response: Response, session: Annotated[AsyncSession, Depends(get_session)]
) -> HealthOut:
    try:
        await session.execute(text("SELECT 1"))
    except SQLAlchemyError:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthOut(status="degraded", database="unavailable", version=__version__)
    return HealthOut(status="ok", database="ok", version=__version__)
