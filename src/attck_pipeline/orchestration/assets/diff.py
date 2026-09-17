from __future__ import annotations

from dagster import AssetExecutionContext, asset

from attck_pipeline.orchestration.resources import MongoResource


@asset
def release_diff(
    context: AssetExecutionContext,
    lineage_edges: dict,
    mongo: MongoResource,
) -> dict:
    """Compute release-to-release diff."""
    from attck_pipeline.checks.diff_checks import check_summary_matches_details
    from attck_pipeline.checks.runner import CheckRunner
    from attck_pipeline.diff.engine import DiffEngine

    release_id = lineage_edges["release_id"]
    release = mongo.db.framework_releases.find_one({"_id": release_id})
    predecessor = release.get("predecessor") if release else None

    if not predecessor:
        context.log.info(f"No predecessor for {release_id}, skipping diff")
        return {"release_id": release_id, "diff_id": None, "skipped": True}

    engine = DiffEngine(mongo.db)
    diff_doc = engine.compute_diff(predecessor, release_id)

    runner = CheckRunner([check_summary_matches_details])
    runner.run_or_raise(diff_doc=diff_doc)

    context.add_output_metadata({
        "diff_id": diff_doc["_id"],
        **diff_doc.get("summary", {}),
    })

    return {"release_id": release_id, "diff_id": diff_doc["_id"], "diff_doc": diff_doc, "skipped": False}


@asset
def sealed_release(
    context: AssetExecutionContext,
    release_diff: dict,
    mongo: MongoResource,
) -> dict:
    """Seal the release with its diff in a transaction."""
    if release_diff.get("skipped"):
        return {"release_id": release_diff["release_id"], "sealed": False}

    from attck_pipeline.diff.engine import DiffEngine

    engine = DiffEngine(mongo.db)
    engine.seal_release(mongo.client, release_diff["release_id"], release_diff["diff_doc"])

    context.add_output_metadata({"release_id": release_diff["release_id"], "sealed": True})
    return {"release_id": release_diff["release_id"], "diff_id": release_diff["diff_id"], "sealed": True}
