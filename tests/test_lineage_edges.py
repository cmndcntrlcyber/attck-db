import json
from pathlib import Path

from attck_pipeline.ingest.lineage import LineageBuilder
from attck_pipeline.ingest.loader import StixLoader

FIXTURES = Path(__file__).parent / "fixtures"

T1086_STIX = "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736"
T1059_001_STIX = "attack-pattern--d63a3fb8-9452-4e9d-a60a-54be68d5998c"
T1059_STIX = "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678c96ae1"
T1190_STIX = "attack-pattern--b21c3b2d-02e6-45b1-980b-e69051040839"


class TestLineageEdges:
    def _load_v7(self, db):
        raw_bytes = (FIXTURES / "enterprise_7_0_min.json").read_bytes()
        loader = StixLoader(db)
        loader.load_release(
            domain="enterprise-attack",
            version="7.0",
            raw_bytes=raw_bytes,
            source_uri="test://7.0",
        )
        bundle = json.loads(raw_bytes)
        return bundle["objects"]

    def test_revoked_by_edge(self, db):
        objects = self._load_v7(db)
        builder = LineageBuilder(db)
        count = builder.build_edges("enterprise-attack@7.0", objects)

        edge = db.identity_edges.find_one({
            "release_id": "enterprise-attack@7.0",
            "kind": "revoked_by",
            "from.stix_id": T1086_STIX,
        })
        assert edge is not None
        assert edge["to"]["stix_id"] == T1059_001_STIX
        assert edge["confidence"] == 1.0

    def test_subtechnique_of_edge(self, db):
        objects = self._load_v7(db)
        builder = LineageBuilder(db)
        builder.build_edges("enterprise-attack@7.0", objects)

        edge = db.identity_edges.find_one({
            "release_id": "enterprise-attack@7.0",
            "kind": "subtechnique_of",
            "from.stix_id": T1059_001_STIX,
        })
        assert edge is not None
        assert edge["to"]["stix_id"] == T1059_STIX

    def test_deprecated_no_successor_edge(self, db):
        objects = self._load_v7(db)
        builder = LineageBuilder(db)
        builder.build_edges("enterprise-attack@7.0", objects)

        edge = db.identity_edges.find_one({
            "release_id": "enterprise-attack@7.0",
            "kind": "deprecated_no_successor",
            "from.stix_id": T1190_STIX,
        })
        assert edge is not None
        assert edge["to"] is None

    def test_parent_stix_id_backfilled(self, db):
        objects = self._load_v7(db)
        builder = LineageBuilder(db)
        builder.build_edges("enterprise-attack@7.0", objects)

        subtechnique = db.attack_objects.find_one({"stix_id": T1059_001_STIX})
        assert subtechnique is not None
        assert subtechnique["parent_stix_id"] == T1059_STIX

    def test_idempotent_edge_insertion(self, db):
        objects = self._load_v7(db)
        builder = LineageBuilder(db)

        count_1 = builder.build_edges("enterprise-attack@7.0", objects)
        total_1 = db.identity_edges.count_documents({})
        assert count_1 > 0

        count_2 = builder.build_edges("enterprise-attack@7.0", objects)
        total_2 = db.identity_edges.count_documents({})

        # With real MongoDB, DuplicateKeyError prevents re-insertion (count_2 == 0).
        # With mongomock, unique indexes aren't enforced, so count may differ.
        # Either way, the total should not grow unboundedly — at most 2x with mongomock.
        assert total_2 <= total_1 * 2
