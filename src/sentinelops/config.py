"""Configuración centralizada. Todo valor sensible llega por variables de entorno (RNF-03)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINELOPS_",
        env_file=".env",
        extra="ignore",
    )

    environment: Literal["dev", "test", "prod"] = "dev"
    database_url: SecretStr = SecretStr(
        "postgresql+asyncpg://sentinelops:sentinelops@localhost:5432/sentinelops"
    )
    # Solo para dev/test: crea las tablas al arrancar. En prod se usa Alembic.
    auto_create_schema: bool = False

    # Límites de ingesta (RNF-02)
    max_batch_events: int = Field(default=500, ge=1, le=5000)
    max_body_bytes: int = Field(default=1_048_576, ge=1024)
    max_future_skew_seconds: int = 300
    max_event_age_days: int = 7

    # Detección
    window_seconds: int = 60
    error_rate_threshold: float = Field(default=0.2, gt=0, le=1)
    latency_p95_threshold_ms: float = 1000.0
    min_events_per_window: int = 10

    # Detectores estadisticos (ADR 0006)
    robust_z_threshold: float = Field(default=3.5, gt=0)
    ewma_alpha: float = Field(default=0.3, gt=0, le=1)
    ewma_factor: float = Field(default=2.0, gt=1)

    # Correlación y diagnóstico
    correlation_gap_seconds: int = 600
    deployment_lookback_seconds: int = 1800

    # CORS cerrado por defecto
    cors_origins: list[str] = []


@lru_cache
def get_settings() -> Settings:
    return Settings()
