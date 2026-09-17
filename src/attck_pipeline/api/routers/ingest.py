from __future__ import annotations

from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks

from attck_pipeline.api.deps import get_settings, get_sync_resources
from attck_pipeline.api.schemas import IngestRequest, TaskAccepted

router = APIRouter()


def _run_ingest_sync(domain: str, version: str):
    settings = get_settings()
    client, db, secure_db = get_sync_resources(settings)
    from attck_pipeline.ingest.lineage import LineageBuilder
    from attck_pipeline.ingest.loader import StixLoader
    from attck_pipeline.sources.mitre_stix import MitreStixSource
    from attck_pipeline.storage import S3Storage

    source = MitreStixSource(settings)
    raw_bytes, sha256 = source.fetch_bundle(domain, version)

    storage = S3Storage(settings)
    loader = StixLoader(db, storage=storage)
    run_id, relationships = loader.load_release(
        domain=domain, version=version, raw_bytes=raw_bytes,
        source_uri=f"mitre-attack/attack-stix-data/{domain}/{domain}-{version}.json",
    )

    if relationships:
        import json
        bundle = json.loads(raw_bytes)
        lineage = LineageBuilder(db)
        lineage.build_edges(f"{domain}@{version}", bundle.get("objects", []))

    client.close()


@router.post("/ingest", status_code=202)
async def trigger_ingest(req: IngestRequest, background_tasks: BackgroundTasks):
    task_id = f"ingest-{uuid4().hex[:12]}"
    background_tasks.add_task(_run_ingest_sync, req.domain, req.version)
    return TaskAccepted(task_id=task_id, message=f"Ingest queued for {req.domain}@{req.version}")
