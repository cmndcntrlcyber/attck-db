from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException

from attck_pipeline.api.deps import get_settings, get_sync_resources
from attck_pipeline.api.schemas import ReportRebuildRequest, TaskAccepted
from attck_pipeline.documents.reports import ReportDoc

router = APIRouter()


@router.get("/{report_id}")
async def get_report(report_id: str):
    report = await ReportDoc.get(report_id)
    if not report:
        raise HTTPException(404, detail=f"Report {report_id} not found")
    return report


def _run_rebuild_sync(report_id: str, verify: bool):
    settings = get_settings()
    client, db, secure_db = get_sync_resources(settings)
    from attck_pipeline.reports.rebuild import ReportRebuilder

    rebuilder = ReportRebuilder(db, secure_db)
    rebuilder.rebuild(report_id, verify=verify)
    client.close()


@router.post("/{report_id}/rebuild", status_code=202)
async def rebuild_report(
    report_id: str,
    req: ReportRebuildRequest,
    background_tasks: BackgroundTasks,
):
    report = await ReportDoc.get(report_id)
    if not report:
        raise HTTPException(404, detail=f"Report {report_id} not found")

    background_tasks.add_task(_run_rebuild_sync, report_id, req.verify)
    return TaskAccepted(task_id=f"rebuild-{uuid4().hex[:8]}", message=f"Rebuild queued for {report_id}")
