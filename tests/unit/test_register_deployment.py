"""Pruebas del caso de uso register_deployment (RF-05)"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sentinelops.application.register_deployment import register_deployment
from sentinelops.domain.errors import InvalidValue
from sentinelops.domain.models import Deployment
from sentinelops.persistence.repositories import InMemoryDeploymentRepository

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


async def test_registers_deployment() -> None:
    repo = InMemoryDeploymentRepository()
    deployment = Deployment(service="checkout", version="v2.4.1", deployed_at=NOW)
    deployment_id = await register_deployment(deployment, repo, now=NOW)
    assert deployment_id is not None
    assert repo.deployments == [deployment]


async def test_rejects_future_deployment() -> None:
    repo = InMemoryDeploymentRepository()
    future = NOW + timedelta(hours=1)
    deployment = Deployment(service="checkout", version="v2.4.1", deployed_at=future)
    with pytest.raises(InvalidValue):
        await register_deployment(deployment, repo, now=NOW)
    assert repo.deployments == []
