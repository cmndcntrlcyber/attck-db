from __future__ import annotations

from datetime import datetime, timezone

import typer
from loguru import logger
from pymongo import MongoClient

from attck_pipeline.config import Settings

app = typer.Typer(name="liszt", help="ATT&CK Knowledge Pipeline for Liszt")


def _get_resources(with_storage: bool = False):
    settings = Settings()
    client = MongoClient(settings.mongo_uri)
    db = client[settings.db_name]
    secure_db = client[settings.db_secure_name]
    storage = None
    if with_storage:
        from attck_pipeline.storage import S3Storage
        storage = S3Storage(settings)
    return settings, client, db, secure_db, storage


@app.command()
def init_db():
    """Initialize database collections, schemas, and indexes."""
    settings, client, db, secure_db, _ = _get_resources()
    from attck_pipeline.db.setup import initialize_database, initialize_secure_database

    initialize_database(db)
    initialize_secure_database(secure_db)
    logger.info("Databases initialized")
    client.close()


@app.command()
def init_storage():
    """Create S3/MinIO buckets for bundles and reports."""
    settings, client, _, _, storage = _get_resources(with_storage=True)
    storage.ensure_buckets()
    logger.info("Storage buckets initialized")
    client.close()


@app.command()
def ingest(domain: str, version: str):
    """Ingest a STIX bundle for a domain and version."""
    settings, client, db, secure_db, storage = _get_resources(with_storage=True)
    from attck_pipeline.ingest.lineage import LineageBuilder
    from attck_pipeline.ingest.loader import StixLoader
    from attck_pipeline.sources.mitre_stix import MitreStixSource

    source = MitreStixSource(settings)
    raw_bytes, sha256 = source.fetch_bundle(domain, version)

    loader = StixLoader(db, storage=storage)
    run_id, relationships = loader.load_release(
        domain=domain,
        version=version,
        raw_bytes=raw_bytes,
        source_uri=f"mitre-attack/attack-stix-data/{domain}/{domain}-{version}.json",
    )

    if relationships:
        release_id = f"{domain}@{version}"
        bundle = __import__("json").loads(raw_bytes)
        lineage = LineageBuilder(db)
        lineage.build_edges(release_id, bundle.get("objects", []))

    logger.info(f"Ingest complete: run_id={run_id}")
    client.close()


@app.command()
def diff(from_release: str, to_release: str):
    """Compute diff between two releases."""
    settings, client, db, secure_db, _ = _get_resources()
    from attck_pipeline.diff.engine import DiffEngine

    engine = DiffEngine(db)
    diff_doc = engine.compute_diff(from_release, to_release)
    engine.seal_release(client, to_release, diff_doc)

    summary = diff_doc["summary"]
    logger.info(
        f"Diff {diff_doc['_id']}: +{summary['added']} revoked:{summary['revoked']} "
        f"deprecated:{summary['deprecated']} modified:{summary['modified']} "
        f"unchanged:{summary['unchanged']}"
    )
    client.close()


@app.command()
def impact(diff_id: str):
    """Detect drift impact from a diff."""
    settings, client, db, secure_db, _ = _get_resources()
    from attck_pipeline.impact.drift import DriftDetector
    from attck_pipeline.impact.notify import NotificationSink

    diff_doc = db.release_diffs.find_one({"_id": diff_id})
    if not diff_doc:
        logger.error(f"Diff {diff_id} not found")
        raise typer.Exit(1)

    detector = DriftDetector(db, secure_db)
    findings = detector.detect_impact(diff_doc)

    sink = NotificationSink()
    sink.notify(findings)
    client.close()


@app.command()
def remap(
    diff_id: str | None = None,
    finding_id: str | None = None,
    auto: bool = False,
):
    """Accept a finding and remap, or bulk auto-remap all eligible findings for a diff."""
    settings, client, db, secure_db, _ = _get_resources()
    from bson import ObjectId

    from attck_pipeline.scenarios.remap import RemapEngine

    engine = RemapEngine(db, secure_db)

    if auto and diff_id:
        result = engine.bulk_auto_remap(client, diff_id)
        logger.info(f"Bulk remap: {result.succeeded}/{result.total} succeeded")
    elif finding_id:
        result = engine.accept_finding(client, ObjectId(finding_id))
        if result.success:
            logger.info(f"Remapped {result.scenario_id} rev {result.old_rev} -> {result.new_rev}")
        else:
            logger.error(f"Remap failed: {result.error}")
    else:
        logger.error("Provide --diff-id with --auto, or --finding-id")
        raise typer.Exit(1)

    client.close()


@app.command()
def overlay_sync():
    """Snapshot the Notion overlay from the live API."""
    settings, client, db, secure_db, storage = _get_resources(with_storage=True)
    from attck_pipeline.sources.notion_overlay import NotionOverlaySource

    if not settings.notion_token:
        logger.error("LISZT_NOTION_TOKEN not set")
        raise typer.Exit(1)

    source = NotionOverlaySource(settings)
    snapshot = source.fetch_snapshot(db=db, storage=storage)
    logger.info(f"Overlay snapshot: {snapshot['_id']} ({len(snapshot['rows'])} rows, sha={snapshot['sha256'][:16]}…)")
    client.close()


@app.command()
def report_build(report_id: str):
    """Render a report from its stored manifest."""
    settings, client, db, secure_db, storage = _get_resources(with_storage=True)
    from attck_pipeline.reports.render import ReportRenderer

    report = secure_db.reports.find_one({"_id": report_id})
    if not report:
        logger.error(f"Report {report_id} not found")
        raise typer.Exit(1)

    renderer = ReportRenderer(db, secure_db, storage=storage)
    result = renderer.render(report)

    secure_db.reports.update_one(
        {"_id": report_id},
        {"$set": {
            "output": {
                "sha256": result.get("pdf_sha256") or result.get("html_sha256") or result["payload_sha256"],
                "bytes": len(result.get("pdf_bytes") or result.get("html_bytes") or result["payload_bytes"]),
                "blob_ref": result.get("blob_ref"),
                "retention": "object-lock",
            }
        }},
    )

    fmt = result["format"]
    sha = result.get(f"{fmt}_sha256") or result["payload_sha256"]
    logger.info(f"Built report {report_id} ({fmt}): {sha[:32]}…")
    client.close()


@app.command()
def report_rebuild(report_id: str, verify: bool = True):
    """Rebuild a report and optionally verify output hash."""
    settings, client, db, secure_db, _ = _get_resources()
    from attck_pipeline.reports.rebuild import ReportRebuilder

    rebuilder = ReportRebuilder(db, secure_db)
    result = rebuilder.rebuild(report_id, verify=verify)

    if result.manifest_match:
        logger.info(f"Manifest hash verified for {report_id}")
    else:
        logger.warning(f"Manifest hash MISMATCH for {report_id}")

    if result.output_match is True:
        logger.info(f"Output hash verified for {report_id}")
    elif result.output_match is False:
        logger.warning(f"Output hash MISMATCH: expected={result.expected_sha256}, got={result.actual_sha256}")

    client.close()


@app.command()
def watch(interval: int = 3600):
    """Poll GitHub for new ATT&CK releases and trigger ingest."""
    settings, client, db, secure_db, storage = _get_resources(with_storage=True)
    settings.watch_interval_seconds = interval
    from attck_pipeline.sources.github_watch import run_watch_loop

    run_watch_loop(settings, db, secure_db, storage=storage)


if __name__ == "__main__":
    app()
