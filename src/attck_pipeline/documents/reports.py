from __future__ import annotations

from datetime import datetime

from beanie import Document


class ReportDoc(Document):
    id: str
    period: dict
    manifest: dict
    manifest_sha256: str
    output: dict | None = None
    generated_at: datetime

    class Settings:
        name = "reports"
