import json
from pathlib import Path

from attck_pipeline.diff.engine import DiffEngine
from attck_pipeline.ingest.lineage import LineageBuilder
from attck_pipeline.ingest.loader import StixLoader

FIXTURES = Path(__file__).parent / "fixtures"

T1086_STIX = "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"
T1059_001_STIX = "attack-pattern--d63a3fb8-9452-4e9d-a60a-54be68d5998c"


class TestDiffRevocation:
    def _load_both(self, db):
        loader = StixLoader(db)

        raw_63 = (FIXTURES / "enterprise_6_3_min.json").read_bytes()
        loader.load_release(
            domain="enterprise-attack",
            version="6.3",
            raw_bytes=raw_63,
            source_uri="test://6.3",
        )

        raw_70 = (FIXTURES / "enterprise_7_0_min.json").read_bytes()
        loader.load_release(
            domain="enterprise-attack",
            version="7.0",
            raw_bytes=raw_70,
            source_uri="test://7.0",
        )

        bundle_70 = json.loads(raw_70)
        lineage = LineageBuilder(db)
        lineage.build_edges("enterprise-attack@7.0", bundle_70["objects"])

    def test_t1086_in_revoked(self, db):
        self._load_both(db)
        engine = DiffEngine(db)
        diff = engine.compute_diff("enterprise-attack@6.3", "enterprise-attack@7.0")

        revoked_ids = {r["stix_id"] for r in diff["revoked"]}
        assert T1086_STIX in revoked_ids

    def test_t1086_has_successor(self, db):
        self._load_both(db)
        engine = DiffEngine(db)
        diff = engine.compute_diff("enterprise-attack@6.3", "enterprise-attack@7.0")

        t1086_entry = next(r for r in diff["revoked"] if r["stix_id"] == T1086_STIX)
        successor_ids = {s["stix_id"] for s in t1086_entry["successors"]}
        assert T1059_001_STIX in successor_ids

    def test_t1059_001_in_added(self, db):
        self._load_both(db)
        engine = DiffEngine(db)
        diff = engine.compute_diff("enterprise-attack@6.3", "enterprise-attack@7.0")

        added_ids = {a["stix_id"] for a in diff["added"]}
        assert T1059_001_STIX in added_ids

    def test_summary_counts(self, db):
        self._load_both(db)
        engine = DiffEngine(db)
        diff = engine.compute_diff("enterprise-attack@6.3", "enterprise-attack@7.0")

        assert diff["summary"]["revoked"] >= 1
        assert diff["summary"]["added"] >= 1

    def test_seal_release(self, db, mongo_client):
        self._load_both(db)
        engine = DiffEngine(db)
        diff = engine.compute_diff("enterprise-attack@6.3", "enterprise-attack@7.0")
        engine.seal_release(mongo_client, "enterprise-attack@7.0", diff)

        release = db.framework_releases.find_one({"_id": "enterprise-attack@7.0"})
        assert release["status"] == "sealed"

        stored_diff = db.release_diffs.find_one({"_id": diff["_id"]})
        assert stored_diff is not None

    def test_diff_idempotent(self, db):
        self._load_both(db)
        engine = DiffEngine(db)

        diff1 = engine.compute_diff("enterprise-attack@6.3", "enterprise-attack@7.0")
        diff2 = engine.compute_diff("enterprise-attack@6.3", "enterprise-attack@7.0")

        assert diff1["summary"] == diff2["summary"]
        assert len(diff1["revoked"]) == len(diff2["revoked"])
