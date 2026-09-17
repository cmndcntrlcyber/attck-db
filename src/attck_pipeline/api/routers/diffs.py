from __future__ import annotations

from fastapi import APIRouter, HTTPException

from attck_pipeline.documents.diffs import ReleaseDiffDoc

router = APIRouter()


@router.get("/{diff_id}")
async def get_diff(diff_id: str):
    diff = await ReleaseDiffDoc.get(diff_id)
    if not diff:
        raise HTTPException(404, detail=f"Diff {diff_id} not found")
    return diff
