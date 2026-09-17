from __future__ import annotations

import json

from dagster import AssetExecutionContext, RetryPolicy, asset

from attck_pipeline.orchestration.resources import MongoResource, S3Resource, SettingsResource


@asset(retry_policy=RetryPolicy(max_retries=3, delay=30))
def stix_bundle(
    context: AssetExecutionContext,
    settings_res: SettingsResource,
) -> dict:
    """Fetch a STIX bundle from MITRE's GitHub repository."""
    settings = settings_res.get_settings()
    from attck_pipeline.sources.mitre_stix import MitreStixSource

    config = context.op_execution_context.op_config
    domain = config.get("domain", "enterprise-attack")
    version = config.get("version", "")

    source = MitreStixSource(settings)
    raw_bytes, sha256 = source.fetch_bundle(domain, version)

    context.add_output_metadata({
        "domain": domain,
        "version": version,
        "bundle_sha256": sha256,
        "bundle_size_bytes": len(raw_bytes),
    })

    return {"raw_bytes_hex": raw_bytes.hex(), "sha256": sha256, "domain": domain, "version": version}


@asset(retry_policy=RetryPolicy(max_retries=2, delay=10))
def stored_bundle(
    context: AssetExecutionContext,
    stix_bundle: dict,
    s3_res: S3Resource,
) -> dict:
    """Store the STIX bundle in S3."""
    storage = s3_res.get_storage()
    raw_bytes = bytes.fromhex(stix_bundle["raw_bytes_hex"])

    stored = storage.put_bundle(
        stix_bundle["domain"], stix_bundle["version"],
        raw_bytes, stix_bundle["sha256"],
    )

    context.add_output_metadata({
        "s3_key": stored.key,
        "s3_bucket": stored.bucket,
    })

    return {"blob_ref": storage.blob_ref(stored.bucket, stored.key), **stix_bundle}


@asset
def loaded_objects(
    context: AssetExecutionContext,
    stix_bundle: dict,
    mongo: MongoResource,
    s3_res: S3Resource,
) -> dict:
    """Load STIX objects into MongoDB."""
    from attck_pipeline.checks.ingest_checks import (
        check_no_duplicate_stix_ids_in_release,
        check_object_count_matches_bundle,
    )
    from attck_pipeline.checks.runner import CheckRunner
    from attck_pipeline.ingest.loader import StixLoader

    raw_bytes = bytes.fromhex(stix_bundle["raw_bytes_hex"])
    storage = s3_res.get_storage()
    loader = StixLoader(mongo.db, storage=storage)

    run_id, relationships = loader.load_release(
        domain=stix_bundle["domain"],
        version=stix_bundle["version"],
        raw_bytes=raw_bytes,
        source_uri=f"mitre-attack/attack-stix-data/{stix_bundle['domain']}/{stix_bundle['domain']}-{stix_bundle['version']}.json",
    )

    release_id = f"{stix_bundle['domain']}@{stix_bundle['version']}"

    runner = CheckRunner([check_object_count_matches_bundle, check_no_duplicate_stix_ids_in_release])
    results = runner.run_or_raise(db=mongo.db, release_id=release_id, raw_bundle=raw_bytes)

    context.add_output_metadata({
        "run_id": run_id,
        "release_id": release_id,
        "relationships_count": len(relationships),
        "checks_passed": len([r for r in results if r.passed]),
    })

    return {"run_id": run_id, "release_id": release_id, "raw_bytes_hex": stix_bundle["raw_bytes_hex"]}


@asset
def lineage_edges(
    context: AssetExecutionContext,
    loaded_objects: dict,
    mongo: MongoResource,
) -> dict:
    """Build identity lineage edges from STIX relationships."""
    import json as json_mod

    from attck_pipeline.checks.lineage_checks import check_revoked_objects_have_edges
    from attck_pipeline.checks.runner import CheckRunner
    from attck_pipeline.ingest.lineage import LineageBuilder

    raw_bytes = bytes.fromhex(loaded_objects["raw_bytes_hex"])
    bundle = json_mod.loads(raw_bytes)
    release_id = loaded_objects["release_id"]

    builder = LineageBuilder(mongo.db)
    count = builder.build_edges(release_id, bundle.get("objects", []))

    runner = CheckRunner([check_revoked_objects_have_edges])
    results = runner.run(db=mongo.db, release_id=release_id)

    context.add_output_metadata({
        "edges_inserted": count,
        "release_id": release_id,
        "checks_passed": len([r for r in results if r.passed]),
    })

    return {"release_id": release_id, "edges_inserted": count}
