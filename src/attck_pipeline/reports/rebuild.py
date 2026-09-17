from __future__ import annotations

from dataclasses import dataclass

from loguru import logger
from pymongo.database import Database

from attck_pipeline.canonical import content_hash
from attck_pipeline.reports.render import ReportRenderer


@dataclass
class RebuildResult:
    report_id: str
    manifest_match: bool
    output_match: bool | None = None
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    error: str | None = None


class ReportRebuilder:
    def __init__(self, db: Database, secure_db: Database):
        self.db = db
        self.secure_db = secure_db
        self.renderer = ReportRenderer(db, secure_db)

    def rebuild(self, report_id: str, verify: bool = True) -> RebuildResult:
        report = self.secure_db.reports.find_one({"_id": report_id})
        if not report:
            return RebuildResult(
                report_id=report_id,
                manifest_match=False,
                error="Report not found",
            )

        recomputed_manifest_sha = content_hash(report["manifest"])
        manifest_match = recomputed_manifest_sha == report["manifest_sha256"]

        if not manifest_match:
            logger.warning(
                f"Manifest hash mismatch for {report_id}: "
                f"stored={report['manifest_sha256']}, recomputed={recomputed_manifest_sha}"
            )

        rendered = self.renderer.render(report)

        if not verify or not report.get("output"):
            return RebuildResult(
                report_id=report_id,
                manifest_match=manifest_match,
                output_match=None,
                actual_sha256=rendered["payload_sha256"],
            )

        stored_sha = report["output"].get("sha256", "")
        output_match = rendered["payload_sha256"] == stored_sha

        if not output_match:
            logger.warning(
                f"Output hash mismatch for {report_id}: "
                f"stored={stored_sha}, rendered={rendered['payload_sha256']}"
            )

        return RebuildResult(
            report_id=report_id,
            manifest_match=manifest_match,
            output_match=output_match,
            expected_sha256=stored_sha,
            actual_sha256=rendered["payload_sha256"],
        )
