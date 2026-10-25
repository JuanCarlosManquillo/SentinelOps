"""Revoca una API key por su id. Deja de autenticar de inmediato (RF-15)

Uso:
    python scripts/revoke_api_key.py --id <uuid>
"""

from __future__ import annotations

import argparse
import asyncio
import uuid
from datetime import UTC, datetime

from sentinelops.config import get_settings
from sentinelops.persistence.database import build_engine, build_sessionmaker
from sentinelops.persistence.repositories import SqlApiKeyRepository


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, type=uuid.UUID)
    args = parser.parse_args()

    settings = get_settings()
    engine = build_engine(settings.database_url.get_secret_value())
    async with build_sessionmaker(engine)() as session:
        await SqlApiKeyRepository(session).revoke(args.id, datetime.now(UTC))
    await engine.dispose()
    print(f"API key {args.id} revocada.")


if __name__ == "__main__":
    asyncio.run(main())
