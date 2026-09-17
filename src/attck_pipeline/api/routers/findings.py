from __future__ import annotations

from uuid import uuid4

from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, HTTPException

from attck_pipeline.api.deps import get_settings, get_sync_resources
from attck_pipeline.api.schemas import FindingAcceptRequest, TaskAccepted
from attck_pipeline.documents.findings import DriftFindingDoc

router = APIRouter()


@router.get("/")
async def list_findings(
    status: str | None = None,
    diff_id: str | None = None,
    skip: int = 0,
    limit: int = 50,
):
    query: dict = {}
    if status:
        query["status"] = status
    if diff_id:
        query["diff_id"] = diff_id
    return await DriftFindingDoc.find(query).skip(skip).limit(limit).to_list()


@router.get("/{finding_id}")
async def get_finding(finding_id: str):
    finding = await DriftFindingDoc.get(ObjectId(finding_id))
    if not finding:
        raise HTTPException(404, detail="Finding not found")
    return finding


def _run_accept_sync(finding_id: str, actor: str):
    settings = get_settings()
    client, db, secure_db = get_sync_resources(settings)
    from attck_pipeline.scenarios.remap import RemapEngine

    engine = RemapEngine(db, secure_db)
    engine.accept_finding(client, ObjectId(finding_id), actor=actor)
    client.close()


@router.post("/{finding_id}/accept", status_code=202)
async def accept_finding(
    finding_id: str,
    req: FindingAcceptRequest,
    background_tasks: BackgroundTasks,
):
    finding = await DriftFindingDoc.get(ObjectId(finding_id))
    if not finding:
        raise HTTPException(404, detail="Finding not found")
    if finding.status != "open":
        raise HTTPException(409, detail=f"Finding status is '{finding.status}', expected 'open'")

    background_tasks.add_task(_run_accept_sync, finding_id, req.actor)
    return TaskAccepted(task_id=f"accept-{finding_id}", message="Remap queued")
