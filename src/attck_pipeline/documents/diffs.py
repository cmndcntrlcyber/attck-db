from __future__ import annotations

from datetime import datetime

from beanie import Document


class ReleaseDiffDoc(Document):
    id: str
    from_release: str
    to_release: str
    algo_version: str
    summary: dict
    revoked: list[dict] = []
    deprecated: list[dict] = []
    added: list[dict] = []
    modified: list[dict] = []
    computed_at: datetime

    class Settings:
        name = "release_diffs"
