from __future__ import annotations

from fastapi import APIRouter, HTTPException

from attck_pipeline.documents.releases import FrameworkReleaseDoc

router = APIRouter()


@router.get("/")
async def list_releases(
    domain: str | None = None,
    status: str | None = None,
    skip: int = 0,
    limit: int = 50,
):
    query: dict = {}
    if domain:
        query["domain"] = domain
    if status:
        query["status"] = status
    releases = await FrameworkReleaseDoc.find(query).skip(skip).limit(limit).to_list()
    return releases


@router.get("/{release_id}")
async def get_release(release_id: str):
    release = await FrameworkReleaseDoc.get(release_id)
    if not release:
        raise HTTPException(404, detail=f"Release {release_id} not found")
    return release
