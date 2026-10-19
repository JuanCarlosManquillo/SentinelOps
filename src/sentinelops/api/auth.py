"""Autenticación por API key con scopes (RNF-01, STRIDE: suplantación y elevación).

- La clave viaja en la cabecera `X-API-Key` y solo se guarda su SHA-256.
  Las claves son aleatorias de 256 bits, así que un hash rápido es adecuado
  (no son contraseñas elegidas por personas).
- Sin clave o clave inválida → 401. Clave válida sin el scope → 403.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelops.api.dependencies import get_session
from sentinelops.persistence.repositories import SqlApiKeyRepository

KEY_PREFIX = "so_"
SCOPES = frozenset({"events:write", "deployments:write", "incidents:read", "incidents:write"})

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def generate_api_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Principal:
    key_id: uuid.UUID
    name: str
    scopes: frozenset[str]


_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="API key ausente o inválida",
    headers={"WWW-Authenticate": "ApiKey"},
)


async def authenticate(
    raw_key: Annotated[str | None, Security(_api_key_header)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Principal:
    if not raw_key or not raw_key.startswith(KEY_PREFIX) or len(raw_key) > 128:
        raise _UNAUTHORIZED
    key_hash = hash_api_key(raw_key)
    row = await SqlApiKeyRepository(session).find_active(key_hash)
    # Comparación en tiempo constante como defensa en profundidad.
    if row is None or not hmac.compare_digest(row.key_hash, key_hash):
        raise _UNAUTHORIZED
    return Principal(key_id=row.id, name=row.name, scopes=frozenset(row.scopes))


def require_scope(scope: str) -> Callable[..., Awaitable[Principal]]:
    if scope not in SCOPES:
        raise ValueError(f"scope desconocido: {scope}")

    async def checker(principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
        if scope not in principal.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"falta el scope {scope}")
        return principal

    return checker
