"""Caso de uso: registrar un despliegue (RF-05)

Valida que la fecha no este en el futuro (defensa ante relojes desfasados) y
delega en el repositorio. El despliegue alimenta la regla `RecentDeploymentRule`
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sentinelops.domain.errors import InvalidValue
from sentinelops.domain.models import Deployment
from sentinelops.domain.ports import DeploymentWriter

MAX_FUTURE_SKEW = timedelta(minutes=5)


async def register_deployment(
    deployment: Deployment,
    writer: DeploymentWriter,
    now: datetime,
    max_future_skew: timedelta = MAX_FUTURE_SKEW,
) -> uuid.UUID:
    """valida la fecha y registra el despliegue (RF-05)"""
    if deployment.deployed_at > now + max_future_skew:
        raise InvalidValue("deployed_at no puede estar en el futuro")
    return await writer.add(deployment)
