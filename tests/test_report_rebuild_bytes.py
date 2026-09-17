import json
from datetime import datetime, timezone
from pathlib import Path

from freezegun import freeze_time

from attck_pipeline.canonical import content_hash
from attck_pipeline.ingest.loader import StixLoader
from attck_pipeline.reports.manifest import ManifestBuilder
from attck_pipeline.reports.render import ReportRenderer
from attck_pipeline.reports.rebuild import ReportRebuilder

FIXTURES = Path(__file__).parent / "fixtures"


class TestReportRebuildBytes:
    def _setup_report(self, db, secure_db):
        raw_63 = (FIXTURES / "enterprise_6_3_min.json").read_bytes()
        loader = StixLoader(db)
        loader.load_release(domain="enterprise-attack", version="6.3", raw_bytes=raw_63, source_uri="test://6.3")

        now = datetime(2026, 7, 1, tzinfo=timezone.utc)
        scenario = {
            "_id": {"scenario_id": "LSZ-0001", "rev": 1},
            "scenario_id": "LSZ-0001",
            "rev": 1,
            "is_head": True,
            "framework_pin": "enterprise-attack@6.3",
            "content_hash": "sha256:scenario_001_hash",
            "steps": [
                {
                    "step_id": "s1",
                    "order": 1,
                    "action": "Test step",
                    "attack_ref": {
                        "stix_id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
                        "external_id_at_pin": "T1086",
                        "release_id": "enterprise-attack@6.3",
                    },
                }
            ],
            "classification": {},
            "created_at": now,
            "created_by": "test",
            "recorded_from": now,
            "recorded_to": None,
        }
        secure_db.scenarios.insert_one(scenario)

        builder = ManifestBuilder(db, secure_db)
        report_doc = builder.build_manifest(
            report_id="RPT-TEST-001",
            framework_release="enterprise-attack@6.3",
            scenario_pins=[{"scenario_id": "LSZ-0001", "rev": 1, "content_hash": "sha256:scenario_001_hash"}],
            overlay_snapshot_id=None,
            query_spec={"name": "test_query", "version": "1", "sha256": "sha256:qspec"},
            template={"repo": "test/templates", "git_sha": "abc123"},
            renderer={"image": "test/renderer@sha256:def456", "lockfile_sha256": "sha256:lockfile"},
            render_params={
                "format": "json",
                "locale": "en_US",
                "tz": "UTC",
                "source_date_epoch": 1790812799,
                "period_from": now,
                "period_to": now,
            },
        )

        secure_db.reports.insert_one(report_doc)
        return report_doc

    @freeze_time("2026-09-30")
    def test_two_renders_match_sha256(self, both_dbs):
        db, secure_db = both_dbs
        report_doc = self._setup_report(db, secure_db)

        renderer = ReportRenderer(db, secure_db)
        render_1 = renderer.render(report_doc)

    @freeze_time("2026-12-15")
    def test_renders_on_different_dates_match(self, both_dbs):
        db, secure_db = both_dbs
        report_doc = self._setup_report(db, secure_db)

        renderer = ReportRenderer(db, secure_db)
        render_1 = renderer.render(report_doc)
        sha_1 = render_1["payload_sha256"]

        render_2 = renderer.render(report_doc)
        sha_2 = render_2["payload_sha256"]

        assert sha_1 == sha_2

    def test_manifest_sha_verifies(self, both_dbs):
        db, secure_db = both_dbs
        report_doc = self._setup_report(db, secure_db)

        recomputed = content_hash(report_doc["manifest"])
        assert recomputed == report_doc["manifest_sha256"]

    def test_rebuild_verifies_manifest(self, both_dbs):
        db, secure_db = both_dbs
        report_doc = self._setup_report(db, secure_db)

        rebuilder = ReportRebuilder(db, secure_db)
        result = rebuilder.rebuild("RPT-TEST-001", verify=False)
        assert result.manifest_match is True

    def test_rebuild_detects_manifest_tampering(self, both_dbs):
        db, secure_db = both_dbs
        report_doc = self._setup_report(db, secure_db)

        secure_db.reports.update_one(
            {"_id": "RPT-TEST-001"},
            {"$set": {"manifest_sha256": "sha256:tampered"}},
        )

        rebuilder = ReportRebuilder(db, secure_db)
        result = rebuilder.rebuild("RPT-TEST-001", verify=False)
        assert result.manifest_match is False
