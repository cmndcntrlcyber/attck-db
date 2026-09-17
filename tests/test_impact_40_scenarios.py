import json
from datetime import datetime, timezone
from pathlib import Path

from attck_pipeline.diff.engine import DiffEngine
from attck_pipeline.impact.drift import DriftDetector
from attck_pipeline.ingest.lineage import LineageBuilder
from attck_pipeline.ingest.loader import StixLoader

FIXTURES = Path(__file__).parent / "fixtures"

T1086_STIX = "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"
T1059_001_STIX = "attack-pattern--d63a3fb8-9452-4e9d-a60a-54be68d5998c"
REPORT_ID = "RPT-2026-Q3-ENT-01"


class TestImpact40Scenarios:
    def _setup_full_pipeline(self, db, secure_db):
        loader = StixLoader(db)

        raw_63 = (FIXTURES / "enterprise_6_3_min.json").read_bytes()
        loader.load_release(domain="enterprise-attack", version="6.3", raw_bytes=raw_63, source_uri="test://6.3")

        raw_70 = (FIXTURES / "enterprise_7_0_min.json").read_bytes()
        loader.load_release(domain="enterprise-attack", version="7.0", raw_bytes=raw_70, source_uri="test://7.0")

        bundle_70 = json.loads(raw_70)
        lineage = LineageBuilder(db)
        lineage.build_edges("enterprise-attack@7.0", bundle_70["objects"])

        scenarios = json.loads((FIXTURES / "scenarios_40.json").read_text())
        now = datetime.now(timezone.utc)
        for s in scenarios:
            s["created_at"] = now
            s["recorded_from"] = now
            secure_db.scenarios.insert_one(s)

            for step in s["steps"]:
                attack_ref = step.get("attack_ref", {})
                if attack_ref:
                    secure_db.scenario_attack_refs.insert_one({
                        "scenario_id": s["scenario_id"],
                        "rev": s["rev"],
                        "is_head": True,
                        "step_id": step["step_id"],
                        "stix_id": attack_ref["stix_id"],
                        "release_id": attack_ref.get("release_id", s["framework_pin"]),
                    })

        scenario_set = [
            {"scenario_id": s["scenario_id"], "rev": s["rev"], "content_hash": s["content_hash"]}
            for s in scenarios
        ]
        secure_db.reports.insert_one({
            "_id": REPORT_ID,
            "period": {"from": now, "to": now},
            "manifest": {
                "framework_release": "enterprise-attack@6.3",
                "framework_bundle_sha256": "sha256:test",
                "scenario_set": scenario_set,
            },
            "manifest_sha256": "sha256:manifest_test",
            "output": None,
            "generated_at": now,
        })

        engine = DiffEngine(db)
        diff = engine.compute_diff("enterprise-attack@6.3", "enterprise-attack@7.0")
        return diff

    def test_exactly_40_findings(self, both_dbs):
        db, secure_db = both_dbs
        diff = self._setup_full_pipeline(db, secure_db)

        detector = DriftDetector(db, secure_db)
        findings = detector.detect_impact(diff)

        technique_revoked = [f for f in findings if f["finding"] == "technique_revoked"]
        assert len(technique_revoked) == 40

    def test_all_auto_remap_eligible(self, both_dbs):
        db, secure_db = both_dbs
        diff = self._setup_full_pipeline(db, secure_db)

        detector = DriftDetector(db, secure_db)
        findings = detector.detect_impact(diff)

        for f in findings:
            if f["finding"] == "technique_revoked":
                assert f["auto_remap_eligible"] is True

    def test_all_have_report_id(self, both_dbs):
        db, secure_db = both_dbs
        diff = self._setup_full_pipeline(db, secure_db)

        detector = DriftDetector(db, secure_db)
        findings = detector.detect_impact(diff)

        for f in findings:
            if f["finding"] == "technique_revoked":
                assert REPORT_ID in f["affected_reports"]

    def test_idempotent_findings(self, both_dbs):
        db, secure_db = both_dbs
        diff = self._setup_full_pipeline(db, secure_db)

        detector = DriftDetector(db, secure_db)
        findings_1 = detector.detect_impact(diff)
        count_1 = secure_db.drift_findings.count_documents({})

        findings_2 = detector.detect_impact(diff)
        count_2 = secure_db.drift_findings.count_documents({})

        assert count_1 == count_2

    def test_proposed_successor(self, both_dbs):
        db, secure_db = both_dbs
        diff = self._setup_full_pipeline(db, secure_db)

        detector = DriftDetector(db, secure_db)
        findings = detector.detect_impact(diff)

        for f in findings:
            if f["finding"] == "technique_revoked":
                assert len(f["proposed"]) == 1
                assert f["proposed"][0]["stix_id"] == T1059_001_STIX
