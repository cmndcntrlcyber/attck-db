from __future__ import annotations

from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from attck_pipeline.config import Settings
from attck_pipeline.documents import PUBLIC_DOCUMENTS, SECURE_DOCUMENTS

_motor_client: AsyncIOMotorClient | None = None


async def init_motor(settings: Settings | None = None) -> AsyncIOMotorClient:
    global _motor_client
    settings = settings or Settings()

    if _motor_client is None:
        _motor_client = AsyncIOMotorClient(settings.mongo_uri)

    await init_beanie(
        database=_motor_client[settings.db_name],
        document_models=PUBLIC_DOCUMENTS,
    )
    await init_beanie(
        database=_motor_client[settings.db_secure_name],
        document_models=SECURE_DOCUMENTS,
    )

    return _motor_client


async def close_motor() -> None:
    global _motor_client
    if _motor_client:
        _motor_client.close()
        _motor_client = None
