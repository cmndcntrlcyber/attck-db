from __future__ import annotations

from dagster import AssetExecutionContext, asset

from attck_pipeline.orchestration.resources import MongoResource


@asset
def drift_findings(
    context: AssetExecutionContext,
    sealed_release: dict,
    mongo: MongoResource,
) -> dict:
    """Detect drift impact on scenarios from the release diff."""
    if not sealed_release.get("sealed"):
        return {"findings_count": 0, "diff_id": None}

    from attck_pipeline.impact.drift import DriftDetector

    diff_id = sealed_release["diff_id"]
    diff_doc = mongo.db.release_diffs.find_one({"_id": diff_id})
    if not diff_doc:
        return {"findings_count": 0, "diff_id": diff_id}

    detector = DriftDetector(mongo.db, mongo.secure_db)
    findings = detector.detect_impact(diff_doc)

    context.add_output_metadata({
        "findings_count": len(findings),
        "auto_remap_eligible": sum(1 for f in findings if f.get("auto_remap_eligible")),
    })

    return {"findings_count": len(findings), "diff_id": diff_id}


@asset
def finding_notifications(
    context: AssetExecutionContext,
    drift_findings: dict,
    mongo: MongoResource,
) -> dict:
    """Send notifications for drift findings."""
    diff_id = drift_findings.get("diff_id")
    if not diff_id or drift_findings["findings_count"] == 0:
        return {"notified": False}

    from attck_pipeline.impact.notify import NotificationSink

    findings = list(mongo.secure_db.drift_findings.find({"diff_id": diff_id}))
    sink = NotificationSink()
    summary = sink.notify(findings)

    context.add_output_metadata({
        "total_findings": summary.total,
        "affected_scenarios": len(summary.affected_scenarios),
    })

    return {"notified": True, "total": summary.total}


@asset
def auto_remap_results(
    context: AssetExecutionContext,
    drift_findings: dict,
    mongo: MongoResource,
) -> dict:
    """Auto-remap eligible findings."""
    diff_id = drift_findings.get("diff_id")
    if not diff_id or drift_findings["findings_count"] == 0:
        return {"remapped": 0, "failed": 0}

    from attck_pipeline.scenarios.remap import RemapEngine

    engine = RemapEngine(mongo.db, mongo.secure_db)
    result = engine.bulk_auto_remap(mongo.client, diff_id)

    context.add_output_metadata({
        "total": result.total,
        "succeeded": result.succeeded,
        "failed": result.failed,
    })

    return {"remapped": result.succeeded, "failed": result.failed}
