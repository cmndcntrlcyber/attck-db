from __future__ import annotations

from dagster import AssetExecutionContext, asset

from attck_pipeline.orchestration.resources import MongoResource, S3Resource


@asset
def rendered_report(
    context: AssetExecutionContext,
    mongo: MongoResource,
    s3_res: S3Resource,
) -> dict:
    """Render a report from its stored manifest."""
    from attck_pipeline.reports.render import ReportRenderer

    config = context.op_execution_context.op_config
    report_id = config.get("report_id", "")

    report = mongo.secure_db.reports.find_one({"_id": report_id})
    if not report:
        context.log.warning(f"Report {report_id} not found")
        return {"report_id": report_id, "rendered": False}

    storage = s3_res.get_storage()
    renderer = ReportRenderer(mongo.db, mongo.secure_db, storage=storage)
    result = renderer.render(report)

    mongo.secure_db.reports.update_one(
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

    context.add_output_metadata({
        "report_id": report_id,
        "format": result["format"],
        "payload_sha256": result["payload_sha256"][:24],
    })

    return {"report_id": report_id, "rendered": True, "format": result["format"]}
