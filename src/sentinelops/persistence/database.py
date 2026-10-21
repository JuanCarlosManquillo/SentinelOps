"""Motor y sesiones asíncronas de SQLAlchemy."""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinelops.persistence.models import Base


def build_engine(url: str) -> AsyncEngine:
    kwargs: dict[str, object] = {"pool_pre_ping": True}
    if url.startswith("postgresql"):
        kwargs |= {"pool_size": 10, "max_overflow": 10}
    return create_async_engine(url, **kwargs)


def build_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def create_schema(engine: AsyncEngine) -> None:
    """Crea el esquema en dev/test. En producción lo gestiona Alembic.

    Alembic es la herramienta que gestiona las migraciones del esquema.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def session_scope(maker: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    async with maker() as session:
        yield session
