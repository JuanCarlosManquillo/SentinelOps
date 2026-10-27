"""POST /api/v1/deployments para registrar un despliegue (RF-05)

El router solo traduce HTTP a casos de uso; la lógica vive en `application`
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.api.auth import Principal, require_scope
from sentinelops.api.dependencies import get_session
from sentinelops.api.schemas import DeploymentIn, DeploymentOut
from sentinelops.application.register_deployment import register_deployment
from sentinelops.persistence.repositories import SqlDeploymentRepository

router = APIRouter(prefix="/api/v1/deployments", tags=["deployments"])


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=DeploymentOut,
    summary="Registra un despliegue",
    description=(
        "Registra un despliegue (servicio, version y fecha). Sirve para que la regla de "
        "diagnostico pueda sospechar de un despliegue reciente. Requiere el scope "
        "deployments:write."
    ),
    responses={
        201: {"description": "Despliegue registrado. Devuelve el id y los datos."},
        401: {"description": "Falta la API key o es invalida."},
        403: {"description": "La API key no tiene el scope deployments:write."},
        422: {"description": "Esquema invalido o fecha en el futuro."},
    },
)
async def post_deployment(
    body: DeploymentIn,
    principal: Annotated[Principal, Depends(require_scope("deployments:write"))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> DeploymentOut:
    deployment = body.to_domain()
    deployment_id = await register_deployment(
        deployment,
        SqlDeploymentRepository(session),
        now=datetime.now(UTC),
    )
    return DeploymentOut(
        id=deployment_id,
        service=deployment.service,
        version=deployment.version,
        deployed_at=deployment.deployed_at,
    )
