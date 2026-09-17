import json
from pathlib import Path

from attck_pipeline.ingest.loader import StixLoader

FIXTURES = Path(__file__).parent / "fixtures"


class TestLoaderIdempotency:
    def test_load_same_bundle_twice_no_change(self, db):
        raw_bytes = (FIXTURES / "enterprise_6_3_min.json").read_bytes()
        loader = StixLoader(db)

        run_id_1, rels_1 = loader.load_release(
            domain="enterprise-attack",
            version="6.3",
            raw_bytes=raw_bytes,
            source_uri="test://6.3",
        )

        count_objects_1 = db.attack_objects.count_documents({})
        count_members_1 = db.release_members.count_documents({})

        run_id_2, rels_2 = loader.load_release(
            domain="enterprise-attack",
            version="6.3",
            raw_bytes=raw_bytes,
            source_uri="test://6.3",
        )

        count_objects_2 = db.attack_objects.count_documents({})
        count_members_2 = db.release_members.count_documents({})

        assert count_objects_1 == count_objects_2
        assert count_members_1 == count_members_2

    def test_loader_creates_framework_release(self, db):
        raw_bytes = (FIXTURES / "enterprise_6_3_min.json").read_bytes()
        loader = StixLoader(db)

        loader.load_release(
            domain="enterprise-attack",
            version="6.3",
            raw_bytes=raw_bytes,
            source_uri="test://6.3",
        )

        release = db.framework_releases.find_one({"_id": "enterprise-attack@6.3"})
        assert release is not None
        assert release["status"] == "staging"
        assert release["domain"] == "enterprise-attack"
        assert release["version"] == "6.3"

    def test_loader_creates_attack_objects(self, db):
        raw_bytes = (FIXTURES / "enterprise_6_3_min.json").read_bytes()
        loader = StixLoader(db)

        loader.load_release(
            domain="enterprise-attack",
            version="6.3",
            raw_bytes=raw_bytes,
            source_uri="test://6.3",
        )

        objects = list(db.attack_objects.find({}))
        assert len(objects) > 0

        t1086 = db.attack_objects.find_one({"external_id": "T1086"})
        assert t1086 is not None
        assert t1086["name"] == "PowerShell"
        assert t1086["kind"] == "technique"
        assert t1086["stix_id"] == "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"

    def test_loader_creates_release_members(self, db):
        raw_bytes = (FIXTURES / "enterprise_6_3_min.json").read_bytes()
        loader = StixLoader(db)

        loader.load_release(
            domain="enterprise-attack",
            version="6.3",
            raw_bytes=raw_bytes,
            source_uri="test://6.3",
        )

        members = list(db.release_members.find({"release_id": "enterprise-attack@6.3"}))
        assert len(members) > 0

        t1086_member = db.release_members.find_one({
            "release_id": "enterprise-attack@6.3",
            "stix_id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
        })
        assert t1086_member is not None
        assert t1086_member["state"] == "active"
        assert t1086_member["external_id"] == "T1086"

    def test_loader_records_ingest_run(self, db):
        raw_bytes = (FIXTURES / "enterprise_6_3_min.json").read_bytes()
        loader = StixLoader(db)

        run_id, _ = loader.load_release(
            domain="enterprise-attack",
            version="6.3",
            raw_bytes=raw_bytes,
            source_uri="test://6.3",
        )

        run = db.ingest_runs.find_one({"_id": run_id})
        assert run is not None
        assert run["status"] == "completed"
        assert run["release_id"] == "enterprise-attack@6.3"

    def test_loader_collects_relationships(self, db):
        raw_bytes = (FIXTURES / "enterprise_7_0_min.json").read_bytes()
        loader = StixLoader(db)

        _, relationships = loader.load_release(
            domain="enterprise-attack",
            version="7.0",
            raw_bytes=raw_bytes,
            source_uri="test://7.0",
        )

        assert len(relationships) == 2
        rel_types = {r["relationship_type"] for r in relationships}
        assert "revoked-by" in rel_types
        assert "subtechnique-of" in rel_types
