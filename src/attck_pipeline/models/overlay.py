from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class TagResult(BaseModel):
    type: str
    value: str
    quarantine_reason: str | None = None
    suggested_fix: str | None = None


class OverlayRow(BaseModel):
    notion_page_id: str
    name: str
    tags: list[TagResult] = []
    attack_reference: str | None = None
    mitigation_reference: str | None = None
    poc_reference: str | None = None
    parent_project: str | None = None
    last_edited_at: str | None = None


class OverlaySnapshot(BaseModel):
    snapshot_id: str
    sha256: str
    rows: list[OverlayRow] = []
    captured_at: datetime
    recorded_from: datetime
    recorded_to: datetime | None = None
