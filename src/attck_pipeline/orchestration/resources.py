from __future__ import annotations

from dagster import ConfigurableResource
from pymongo import MongoClient

from attck_pipeline.config import Settings
from attck_pipeline.storage import S3Storage


class SettingsResource(ConfigurableResource):
    def get_settings(self) -> Settings:
        return Settings()


class MongoResource(ConfigurableResource):
    mongo_uri: str = "mongodb://localhost:27017"
    db_name: str = "liszt"
    db_secure_name: str = "liszt_secure"

    _client: MongoClient | None = None

    def _get_client(self) -> MongoClient:
        if self._client is None:
            self._client = MongoClient(self.mongo_uri)
        return self._client

    @property
    def db(self):
        return self._get_client()[self.db_name]

    @property
    def secure_db(self):
        return self._get_client()[self.db_secure_name]

    @property
    def client(self) -> MongoClient:
        return self._get_client()

    def teardown_after_execution(self, context) -> None:
        if self._client:
            self._client.close()
            self._client = None


class S3Resource(ConfigurableResource):
    def get_storage(self) -> S3Storage:
        return S3Storage(Settings())
