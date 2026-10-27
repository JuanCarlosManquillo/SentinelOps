"""Fábrica de la aplicación FastAPI (punto de composición de la API)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sentinelops import __version__
from sentinelops.api.errors import register_error_handlers
from sentinelops.api.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from sentinelops.api.routes import deployments, events, health
from sentinelops.config import Settings, get_settings
from sentinelops.persistence.database import build_engine, build_sessionmaker, create_schema

API_DESCRIPTION = (
    "SentinelOps recibe eventos (logs, metricas, errores HTTP), detecta anomalias, "
    "las agrupa en incidentes y propone causas probables con evidencias.\n\n"
    "**Autenticacion:** las rutas de datos piden la cabecera `X-API-Key`. "
    "Usa el boton **Authorize** (arriba a la derecha) para probar desde aqui."
)

# Descripcion de cada grupo de endpoints que se ve en Swagger.
TAGS_METADATA = [
    {"name": "health", "description": "Estado del servicio y de la base de datos."},
    {
        "name": "events",
        "description": "Ingesta de eventos por lotes. Requiere el scope events:write.",
    },
    {
        "name": "deployments",
        "description": "Registro de despliegues. Requiere el scope deployments:write.",
    },
]


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = build_engine(settings.database_url.get_secret_value())
        if settings.auto_create_schema:
            await create_schema(engine)
        app.state.engine = engine
        app.state.sessionmaker = build_sessionmaker(engine)
        yield
        await engine.dispose()

    is_prod = settings.environment == "prod"
    app = FastAPI(
        title="SentinelOps",
        version=__version__,
        description=API_DESCRIPTION,
        openapi_tags=TAGS_METADATA,
        lifespan=lifespan,
        # En producción la documentación interactiva se desactiva.
        docs_url=None if is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if is_prod else "/openapi.json",
    )
    app.state.settings = settings

    # El último middleware añadido es el más externo: el límite de cuerpo actúa primero.
    app.add_middleware(SecurityHeadersMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=["X-API-Key", "Content-Type"],
        )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)

    register_error_handlers(app)
    app.include_router(health.router)
    app.include_router(events.router)
    # Se añade el router de despliegues con el fin de registrar un despliegue a traves de la API
    app.include_router(deployments.router)
    return app


app = create_app()
