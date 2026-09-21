from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException

from attck_pipeline.api.deps import get_settings, get_sync_resources
from attck_pipeline.api.schemas import TaskAccepted
from attck_pipeline.documents.overlays import OverlaySnapshotDoc
from attck_pipeline.sources.nemesis_mapping import get_all_mappings

router = APIRouter()


@router.get("/latest")
async def get_latest_nemesis_snapshot():
    snapshot = await OverlaySnapshotDoc.find(
        {"_id": {"$regex": "^nemesis-"}},
    ).sort("-captured_at").first_or_none()
    if not snapshot:
        raise HTTPException(404, detail="No Nemesis snapshot found")
    return snapshot


@router.get("/mappings")
async def list_mappings():
    return get_all_mappings()


def _run_nemesis_sync():
    settings = get_settings()
    client, db, secure_db = get_sync_resources(settings)
    from attck_pipeline.sources.nemesis_source import NemesisSource
    from attck_pipeline.storage import S3Storage

    storage = S3Storage(settings)
    source = NemesisSource(settings)
    source.fetch_snapshot(db=db, storage=storage)
    client.close()


@router.post("/sync", status_code=202)
async def trigger_nemesis_sync(background_tasks: BackgroundTasks):
    background_tasks.add_task(_run_nemesis_sync)
    return TaskAccepted(
        task_id=f"nemesis-sync-{uuid4().hex[:8]}",
        message="Nemesis sync queued",
    )
