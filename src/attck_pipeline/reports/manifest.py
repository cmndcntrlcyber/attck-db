from __future__ import annotations

from datetime import datetime, timezone

from pymongo.database import Database

from attck_pipeline.canonical import content_hash


class ManifestBuilder:
    def __init__(self, db: Database, secure_db: Database):
        self.db = db
        self.secure_db = secure_db

    def build_manifest(
        self,
        report_id: str,
        framework_release: str,
        scenario_pins: list[dict],
        overlay_snapshot_id: str | None,
        query_spec: dict,
        template: dict,
        renderer: dict,
        render_params: dict,
    ) -> dict:
        release = self.db.framework_releases.find_one({"_id": framework_release})
        bundle_sha256 = release["source"]["sha256"] if release else ""

        overlay_snap = None
        if overlay_snapshot_id:
            snap = self.db.overlay_snapshots.find_one({"_id": overlay_snapshot_id})
            if snap:
                overlay_snap = {
                    "snapshot_id": overlay_snapshot_id,
                    "sha256": snap["sha256"],
                }

        period_from = render_params.pop("period_from", None)
        period_to = render_params.pop("period_to", None)

        manifest = {
            "framework_release": framework_release,
            "framework_bundle_sha256": bundle_sha256,
            "scenario_set": sorted(scenario_pins, key=lambda s: (s["scenario_id"], s["rev"])),
            "overlay_snapshot": overlay_snap,
            "query_spec": query_spec,
            "template": template,
            "renderer": renderer,
            "render_params": render_params,
        }

        manifest_sha256 = content_hash(manifest)
        now = datetime.now(timezone.utc)

        report_doc = {
            "_id": report_id,
            "period": {
                "from": period_from or now,
                "to": period_to or now,
            },
            "manifest": manifest,
            "manifest_sha256": manifest_sha256,
            "output": None,
            "generated_at": now,
        }

        return report_doc
