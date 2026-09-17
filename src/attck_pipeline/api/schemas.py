from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class IngestRequest(BaseModel):
    domain: str
    version: str


class FindingAcceptRequest(BaseModel):
    actor: str = "api-user"


class ReportRebuildRequest(BaseModel):
    verify: bool = True


class TaskAccepted(BaseModel):
    task_id: str
    status: str = "accepted"
    message: str


class ReleaseListItem(BaseModel):
    id: str
    domain: str
    version: str
    status: str
    ingested_at: datetime

    class Config:
        from_attributes = True
