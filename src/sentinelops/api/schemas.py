"""Contratos HTTP (Pydantic). Separados de las entidades de dominio a propósito.

`extra="forbid"` rechaza campos desconocidos y `AwareDatetime` exige zona horaria (RF-02).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from sentinelops.domain.models import Deployment, Event, EventKind, Severity

ServiceName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")]
AttributeValue = str | int | float | bool | None


class EventIn(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "examples": [
                {
                    "service": "checkout",
                    "version": "v2.4.1",
                    "deployed_at": "2026-10-25T10:00:00Z",
                }
            ]
        },
    )

    schema_version: Literal["1.0"] = "1.0"
    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:\-]+$")
    service: ServiceName
    kind: EventKind
    severity: Literal["debug", "info", "warning", "error", "critical"]
    occurred_at: AwareDatetime
    message: str = Field(default="", max_length=2000)
    attributes: dict[
        Annotated[str, Field(max_length=100)],
        Annotated[AttributeValue, Field(union_mode="left_to_right")],
    ] = Field(default_factory=dict, max_length=50)
    trace_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")

    def to_domain(self) -> Event:
        return Event(
            event_id=self.event_id,
            service=self.service,
            kind=self.kind,
            severity=Severity.parse(self.severity),
            occurred_at=self.occurred_at,
            message=self.message,
            attributes=dict(self.attributes),
            trace_id=self.trace_id,
        )


class EventBatchIn(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "events": [
                        {
                            "event_id": "checkout-00001",
                            "service": "checkout",
                            "kind": "http_error",
                            "severity": "error",
                            "occurred_at": "2026-10-25T10:00:01Z",
                            "message": "upstream unavailable",
                            "attributes": {"http.status_code": 503, "latency_ms": 1840},
                        }
                    ]
                }
            ]
        },
    )

    # El máximo efectivo lo fija la configuración; 500 es el valor por defecto (RNF-02).
    events: list[EventIn] = Field(min_length=1, max_length=500)


class IngestOut(BaseModel):
    received: int
    inserted: int
    duplicates: int


class DeploymentIn(BaseModel):
    """Para registrar un desploegue y asegurar reglas de diagnóstico (RF-05)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    service: ServiceName
    version: str = Field(min_length=1, max_length=64)
    deployed_at: AwareDatetime

    def to_domain(self) -> Deployment:
        return Deployment(
            service=self.service,
            version=self.version,
            deployed_at=self.deployed_at,
        )


class DeploymentOut(BaseModel):
    id: uuid.UUID
    service: str
    version: str
    deployed_at: datetime


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    database: Literal["ok", "unavailable"]
    version: str
