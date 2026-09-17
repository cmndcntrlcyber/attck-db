from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException

from attck_pipeline.api.deps import get_settings, get_sync_resources
from attck_pipeline.api.schemas import TaskAccepted
from attck_pipeline.documents.overlays import OverlaySnapshotDoc

router = APIRouter()


@router.get("/latest")
async def get_latest_overlay():
    snapshot = await OverlaySnapshotDoc.find(
        OverlaySnapshotDoc.recorded_to == None,  # noqa: E711
    ).sort("-captured_at").first_or_none()
    if not snapshot:
        raise HTTPException(404, detail="No overlay snapshot found")
    return snapshot


def _run_overlay_sync():
    settings = get_settings()
    client, db, secure_db = get_sync_resources(settings)
    from attck_pipeline.sources.notion_overlay import NotionOverlaySource
    from attck_pipeline.storage import S3Storage

    storage = S3Storage(settings)
    source = NotionOverlaySource(settings)
    source.fetch_snapshot(db=db, storage=storage)
    client.close()


@router.post("/sync", status_code=202)
async def trigger_overlay_sync(background_tasks: BackgroundTasks):
    background_tasks.add_task(_run_overlay_sync)
    return TaskAccepted(task_id=f"overlay-sync-{uuid4().hex[:8]}", message="Overlay sync queued")
