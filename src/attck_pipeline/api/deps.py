from __future__ import annotations

from functools import lru_cache

from pymongo import MongoClient

from attck_pipeline.config import Settings


@lru_cache
def get_settings() -> Settings:
    return Settings()


def get_sync_resources(settings: Settings | None = None):
    s = settings or get_settings()
    client = MongoClient(s.mongo_uri)
    db = client[s.db_name]
    secure_db = client[s.db_secure_name]
    return client, db, secure_db
