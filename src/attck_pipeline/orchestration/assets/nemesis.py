from __future__ import annotations

from dagster import AssetExecutionContext, RetryPolicy, asset

from attck_pipeline.orchestration.resources import MongoResource, S3Resource, SettingsResource


@asset(retry_policy=RetryPolicy(max_retries=3, delay=30))
def nemesis_snapshot(
    context: AssetExecutionContext,
    settings_res: SettingsResource,
    mongo: MongoResource,
    s3_res: S3Resource,
) -> dict:
    """Sync findings from Nemesis into an overlay snapshot."""
    from attck_pipeline.checks.overlay_checks import check_snapshot_hash_verifiable
    from attck_pipeline.checks.runner import CheckRunner
    from attck_pipeline.sources.nemesis_source import NemesisSource

    settings = settings_res.get_settings()
    storage = s3_res.get_storage()
    source = NemesisSource(settings)
    snapshot = source.fetch_snapshot(db=mongo.db, storage=storage)

    runner = CheckRunner([check_snapshot_hash_verifiable])
    runner.run_or_raise(snapshot=snapshot)

    quarantine_count = mongo.db.ingest_quarantine.count_documents({"source": "nemesis"})

    context.add_output_metadata({
        "snapshot_id": snapshot["_id"],
        "findings_count": len(snapshot.get("rows", [])),
        "sha256": snapshot["sha256"][:24],
        "quarantine_entries": quarantine_count,
    })

    return {"snapshot_id": snapshot["_id"], "findings_count": len(snapshot.get("rows", []))}
