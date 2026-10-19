"""Crea una API key y muestra la clave en claro UNA sola vez.

Uso:
    python scripts/create_api_key.py --name seed-client --scopes events:write incidents:read
"""

from __future__ import annotations

import argparse
import asyncio

from sentinelops.api.auth import SCOPES, generate_api_key, hash_api_key
from sentinelops.config import get_settings
from sentinelops.persistence.database import build_engine, build_sessionmaker, create_schema
from sentinelops.persistence.repositories import SqlApiKeyRepository


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--scopes", nargs="+", required=True, choices=sorted(SCOPES))
    args = parser.parse_args()

    settings = get_settings()
    engine = build_engine(settings.database_url.get_secret_value())
    if settings.auto_create_schema:
        await create_schema(engine)
    raw = generate_api_key()
    async with build_sessionmaker(engine)() as session:
        row = await SqlApiKeyRepository(session).create(args.name, hash_api_key(raw), args.scopes)
    await engine.dispose()
    print(f"id: {row.id}\nscopes: {', '.join(args.scopes)}\nAPI key (guárdala ahora): {raw}")


if __name__ == "__main__":
    asyncio.run(main())
