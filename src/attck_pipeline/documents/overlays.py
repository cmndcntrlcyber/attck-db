from __future__ import annotations

from datetime import datetime

from beanie import Document


class OverlaySnapshotDoc(Document):
    id: str
    sha256: str
    rows: list[dict] = []
    captured_at: datetime
    recorded_from: datetime
    recorded_to: datetime | None = None

    class Settings:
        name = "overlay_snapshots"
