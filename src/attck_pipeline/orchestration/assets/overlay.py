from __future__ import annotations

from dagster import AssetExecutionContext, RetryPolicy, asset

from attck_pipeline.orchestration.resources import MongoResource, S3Resource, SettingsResource


@asset(retry_policy=RetryPolicy(max_retries=3, delay=30))
def overlay_snapshot(
    context: AssetExecutionContext,
    settings_res: SettingsResource,
    mongo: MongoResource,
    s3_res: S3Resource,
) -> dict:
    """Fetch and store a Notion overlay snapshot."""
    from attck_pipeline.checks.overlay_checks import check_snapshot_hash_verifiable
    from attck_pipeline.checks.runner import CheckRunner
    from attck_pipeline.sources.notion_overlay import NotionOverlaySource

    settings = settings_res.get_settings()
    storage = s3_res.get_storage()
    source = NotionOverlaySource(settings)
    snapshot = source.fetch_snapshot(db=mongo.db, storage=storage)

    runner = CheckRunner([check_snapshot_hash_verifiable])
    runner.run_or_raise(snapshot=snapshot)

    context.add_output_metadata({
        "snapshot_id": snapshot["_id"],
        "row_count": len(snapshot.get("rows", [])),
        "sha256": snapshot["sha256"][:24],
    })

    return {"snapshot_id": snapshot["_id"], "row_count": len(snapshot.get("rows", []))}
