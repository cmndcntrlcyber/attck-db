from __future__ import annotations

from datetime import datetime
from typing import Literal

from beanie import Document


class IngestQuarantineDoc(Document):
    value: str
    source: str
    reason: str
    suggested_fix: str | None = None
    created_at: datetime

    class Settings:
        name = "ingest_quarantine"


class IngestRunDoc(Document):
    id: str
    release_id: str
    status: Literal["running", "completed", "failed"]
    started_at: datetime
    completed_at: datetime | None = None
    counts: dict = {}
    duration_ms: int | None = None
    error: str | None = None

    class Settings:
        name = "ingest_runs"
