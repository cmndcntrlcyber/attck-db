import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from attck_pipeline.diff.engine import DiffEngine
from attck_pipeline.impact.drift import DriftDetector
from attck_pipeline.ingest.lineage import LineageBuilder
from attck_pipeline.ingest.loader import StixLoader
from attck_pipeline.scenarios.remap import RemapEngine


FIXTURES = Path(__file__).parent / "fixtures"

T1086_STIX = "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"
T1059_001_STIX = "attack-pattern--d63a3fb8-9452-4e9d-a60a-54be68d5998c"


class TestRemapRevision:
    def _setup(self, db, secure_db):
        loader = StixLoader(db)

        raw_63 = (FIXTURES / "enterprise_6_3_min.json").read_bytes()
        loader.load_release(domain="enterprise-attack", version="6.3", raw_bytes=raw_63, source_uri="test://6.3")

        raw_70 = (FIXTURES / "enterprise_7_0_min.json").read_bytes()
        loader.load_release(domain="enterprise-attack", version="7.0", raw_bytes=raw_70, source_uri="test://7.0")

        bundle_70 = json.loads(raw_70)
        lineage = LineageBuilder(db)
        lineage.build_edges("enterprise-attack@7.0", bundle_70["objects"])

        now = datetime.now(timezone.utc)
        scenario = {
            "_id": {"scenario_id": "LSZ-0142", "rev": 3},
            "scenario_id": "LSZ-0142",
            "rev": 3,
            "is_head": True,
            "framework_pin": "enterprise-attack@6.3",
            "content_hash": "sha256:original_hash_0142",
            "steps": [
                {
                    "step_id": "s4",
                    "order": 4,
                    "action": "Encoded PowerShell download cradle",
                    "attack_ref": {
                        "stix_id": T1086_STIX,
                        "external_id_at_pin": "T1086",
                        "release_id": "enterprise-attack@6.3",
                    },
                }
            ],
            "classification": {"sensitivity": "Client-Confidential", "owner": "test"},
            "created_at": now,
            "created_by": "test-harness",
            "recorded_from": now,
            "recorded_to": None,
        }
        secure_db.scenarios.insert_one(scenario)

        secure_db.scenario_attack_refs.insert_one({
            "scenario_id": "LSZ-0142",
            "rev": 3,
            "is_head": True,
            "step_id": "s4",
            "stix_id": T1086_STIX,
            "release_id": "enterprise-attack@6.3",
        })

        secure_db.reports.insert_one({
            "_id": "RPT-2026-Q3-ENT-01",
            "period": {"from": now, "to": now},
            "manifest": {
                "framework_release": "enterprise-attack@6.3",
                "framework_bundle_sha256": "sha256:test",
                "scenario_set": [{"scenario_id": "LSZ-0142", "rev": 3, "content_hash": "sha256:original_hash_0142"}],
            },
            "manifest_sha256": "sha256:manifest_test",
            "output": None,
            "generated_at": now,
        })

        engine = DiffEngine(db)
        diff = engine.compute_diff("enterprise-attack@6.3", "enterprise-attack@7.0")

        detector = DriftDetector(db, secure_db)
        findings = detector.detect_impact(diff)

        return findings

    def test_remap_creates_new_revision(self, both_dbs, mongo_client):
        db, secure_db = both_dbs
        findings = self._setup(db, secure_db)

        technique_findings = [f for f in findings if f["finding"] == "technique_revoked"]
        assert len(technique_findings) == 1
        finding = technique_findings[0]
        finding_id = secure_db.drift_findings.find_one({
            "diff_id": finding["diff_id"],
            "scenario_id": "LSZ-0142",
        })["_id"]

        engine = RemapEngine(db, secure_db)
        result = engine.accept_finding(mongo_client, finding_id)

        assert result.success is True
        assert result.new_rev == 4
        assert result.old_rev == 3

    def test_old_revision_unchanged(self, both_dbs, mongo_client):
        db, secure_db = both_dbs
        findings = self._setup(db, secure_db)

        old_rev3 = secure_db.scenarios.find_one({"_id": {"scenario_id": "LSZ-0142", "rev": 3}})
        original_hash = old_rev3["content_hash"]

        finding_id = secure_db.drift_findings.find_one({"scenario_id": "LSZ-0142"})["_id"]
        engine = RemapEngine(db, secure_db)
        engine.accept_finding(mongo_client, finding_id)

        rev3_after = secure_db.scenarios.find_one({"_id": {"scenario_id": "LSZ-0142", "rev": 3}})
        assert rev3_after["content_hash"] == original_hash
        assert rev3_after["is_head"] is False

    def test_new_revision_points_to_successor(self, both_dbs, mongo_client):
        db, secure_db = both_dbs
        self._setup(db, secure_db)

        finding_id = secure_db.drift_findings.find_one({"scenario_id": "LSZ-0142"})["_id"]
        engine = RemapEngine(db, secure_db)
        engine.accept_finding(mongo_client, finding_id)

        rev4 = secure_db.scenarios.find_one({"_id": {"scenario_id": "LSZ-0142", "rev": 4}})
        assert rev4 is not None
        assert rev4["is_head"] is True
        assert rev4["framework_pin"] == "enterprise-attack@7.0"

        step = rev4["steps"][0]
        assert step["attack_ref"]["stix_id"] == T1059_001_STIX

    def test_finding_status_accepted(self, both_dbs, mongo_client):
        db, secure_db = both_dbs
        self._setup(db, secure_db)

        finding_id = secure_db.drift_findings.find_one({"scenario_id": "LSZ-0142"})["_id"]
        engine = RemapEngine(db, secure_db)
        engine.accept_finding(mongo_client, finding_id)

        finding = secure_db.drift_findings.find_one({"_id": finding_id})
        assert finding["status"] == "accepted"
        assert finding["resolution"]["new_scenario_rev"] == 4

    def test_attack_refs_updated(self, both_dbs, mongo_client):
        db, secure_db = both_dbs
        self._setup(db, secure_db)

        finding_id = secure_db.drift_findings.find_one({"scenario_id": "LSZ-0142"})["_id"]
        engine = RemapEngine(db, secure_db)
        engine.accept_finding(mongo_client, finding_id)

        old_refs = list(secure_db.scenario_attack_refs.find({"scenario_id": "LSZ-0142", "rev": 3}))
        assert all(r["is_head"] is False for r in old_refs)

        new_refs = list(secure_db.scenario_attack_refs.find({"scenario_id": "LSZ-0142", "rev": 4}))
        assert len(new_refs) == 1
        assert new_refs[0]["stix_id"] == T1059_001_STIX
        assert new_refs[0]["is_head"] is True
