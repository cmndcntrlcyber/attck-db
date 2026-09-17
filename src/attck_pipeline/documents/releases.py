from __future__ import annotations

from datetime import datetime
from typing import Literal

from beanie import Document
from pydantic import BaseModel


class ReleaseSource(BaseModel):
    uri: str
    git_ref: str = ""
    sha256: str
    blob_ref: str | None = None


class FrameworkReleaseDoc(Document):
    id: str
    domain: str
    version: str
    predecessor: str | None = None
    released_at: datetime
    source: ReleaseSource
    counts: dict = {}
    ingest_run_id: str
    ingested_at: datetime
    status: Literal["staging", "sealed"]

    class Settings:
        name = "framework_releases"
