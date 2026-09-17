import pytest
from pymongo.errors import WriteError

from attck_pipeline.canonical import content_hash

pytestmark = pytest.mark.requires_real_mongo


SAMPLE_RAW = {
    "type": "attack-pattern",
    "id": "attack-pattern--test-001",
    "name": "Test Technique",
    "modified": "2024-01-01T00:00:00.000Z",
}


def _valid_technique(stix_id="attack-pattern--test-001"):
    raw = {**SAMPLE_RAW, "id": stix_id}
    return {
        "_id": content_hash(raw),
        "stix_id": stix_id,
        "stix_type": "attack-pattern",
        "kind": "technique",
        "external_id": "T9999",
        "name": "Test Technique",
        "modified": "2024-01-01T00:00:00.000Z",
        "x_mitre_version": "1.0",
        "revoked": False,
        "deprecated": False,
        "parent_stix_id": None,
        "tactic_shortnames": ["execution"],
        "platforms": ["Windows"],
        "description": "A test technique.",
        "raw": raw,
    }


def _valid_tactic(stix_id="x-mitre-tactic--test-001"):
    raw = {"type": "x-mitre-tactic", "id": stix_id, "name": "Test Tactic", "modified": "2024-01-01T00:00:00.000Z"}
    return {
        "_id": content_hash(raw),
        "stix_id": stix_id,
        "stix_type": "x-mitre-tactic",
        "kind": "tactic",
        "external_id": "TA9999",
        "name": "Test Tactic",
        "modified": "2024-01-01T00:00:00.000Z",
        "x_mitre_version": "1.0",
        "revoked": False,
        "deprecated": False,
        "parent_stix_id": None,
        "tactic_shortnames": None,
        "platforms": None,
        "description": "A test tactic.",
        "x_mitre_shortname": "test-tactic",
        "raw": raw,
    }


class TestAttackObjectsSchema:
    def test_valid_technique_inserts(self, db):
        db.attack_objects.insert_one(_valid_technique())
        assert db.attack_objects.count_documents({}) == 1

    def test_valid_tactic_inserts(self, db):
        db.attack_objects.insert_one(_valid_tactic())
        assert db.attack_objects.count_documents({}) == 1

    def test_technique_missing_tactic_shortnames_rejected(self, db):
        doc = _valid_technique()
        del doc["tactic_shortnames"]
        with pytest.raises(WriteError):
            db.attack_objects.insert_one(doc)

    def test_tactic_missing_shortname_rejected(self, db):
        doc = _valid_tactic()
        del doc["x_mitre_shortname"]
        with pytest.raises(WriteError):
            db.attack_objects.insert_one(doc)

    def test_invalid_kind_rejected(self, db):
        doc = _valid_technique()
        doc["kind"] = "invalid_kind"
        with pytest.raises(WriteError):
            db.attack_objects.insert_one(doc)

    def test_missing_name_rejected(self, db):
        doc = _valid_technique()
        del doc["name"]
        with pytest.raises(WriteError):
            db.attack_objects.insert_one(doc)


class TestFrameworkReleasesSchema:
    def test_valid_release_inserts(self, db):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        db.framework_releases.insert_one({
            "_id": "enterprise-attack@7.0",
            "domain": "enterprise-attack",
            "version": "7.0",
            "predecessor": "enterprise-attack@6.3",
            "released_at": now,
            "source": {
                "uri": "https://example.com/bundle.json",
                "git_ref": "abc123",
                "sha256": "sha256:abc",
                "blob_ref": None,
            },
            "counts": {},
            "ingest_run_id": "run-001",
            "ingested_at": now,
            "status": "staging",
        })
        assert db.framework_releases.count_documents({}) == 1

    def test_invalid_status_rejected(self, db):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        with pytest.raises(WriteError):
            db.framework_releases.insert_one({
                "_id": "enterprise-attack@7.0",
                "domain": "enterprise-attack",
                "version": "7.0",
                "source": {"uri": "x", "sha256": "y"},
                "ingested_at": now,
                "status": "invalid_status",
            })


class TestReleaseMembersSchema:
    def test_valid_member_inserts(self, db):
        db.release_members.insert_one({
            "_id": {"r": "enterprise-attack@7.0", "s": "attack-pattern--test-001"},
            "release_id": "enterprise-attack@7.0",
            "stix_id": "attack-pattern--test-001",
            "external_id": "T9999",
            "object_hash": "sha256:abc",
            "state": "active",
        })
        assert db.release_members.count_documents({}) == 1

    def test_invalid_state_rejected(self, db):
        with pytest.raises(WriteError):
            db.release_members.insert_one({
                "_id": {"r": "r", "s": "s"},
                "release_id": "r",
                "stix_id": "s",
                "object_hash": "h",
                "state": "invalid",
            })


class TestDriftFindingsSchema:
    def test_valid_finding_inserts(self, secure_db):
        secure_db.drift_findings.insert_one({
            "diff_id": "enterprise-attack@6.3..enterprise-attack@7.0",
            "scenario_id": "LSZ-0101",
            "scenario_rev": 3,
            "step_id": "s1",
            "finding": "technique_revoked",
            "from": {"stix_id": "attack-pattern--test-001", "external_id": "T1086"},
            "proposed": [],
            "auto_remap_eligible": True,
            "affected_reports": [],
            "status": "open",
            "resolution": None,
        })
        assert secure_db.drift_findings.count_documents({}) == 1

    def test_invalid_finding_type_rejected(self, secure_db):
        with pytest.raises(WriteError):
            secure_db.drift_findings.insert_one({
                "diff_id": "d",
                "scenario_id": "s",
                "scenario_rev": 1,
                "step_id": "s1",
                "finding": "invalid_type",
                "from": {},
                "proposed": [],
                "auto_remap_eligible": False,
                "affected_reports": [],
                "status": "open",
                "resolution": None,
            })


class TestIndexes:
    def test_identity_edges_unique_index(self, db):
        db.identity_edges.insert_one({
            "release_id": "enterprise-attack@7.0",
            "kind": "revoked_by",
            "from": {"stix_id": "a", "external_id": "T1"},
            "to": {"stix_id": "b", "external_id": "T2"},
            "evidence": {"source": "test"},
            "confidence": 1.0,
        })
        from pymongo.errors import DuplicateKeyError

        with pytest.raises(DuplicateKeyError):
            db.identity_edges.insert_one({
                "release_id": "enterprise-attack@7.0",
                "kind": "revoked_by",
                "from": {"stix_id": "a", "external_id": "T1"},
                "to": {"stix_id": "b", "external_id": "T2"},
                "evidence": {"source": "test"},
                "confidence": 1.0,
            })

    def test_drift_findings_unique_index(self, secure_db):
        doc = {
            "diff_id": "d1",
            "scenario_id": "s1",
            "scenario_rev": 1,
            "step_id": "step1",
            "finding": "technique_revoked",
            "from": {"stix_id": "a"},
            "proposed": [],
            "auto_remap_eligible": False,
            "affected_reports": [],
            "status": "open",
            "resolution": None,
        }
        secure_db.drift_findings.insert_one(doc.copy())
        from pymongo.errors import DuplicateKeyError

        with pytest.raises(DuplicateKeyError):
            secure_db.drift_findings.insert_one(doc.copy())

    def test_release_members_indexes_exist(self, db):
        indexes = db.release_members.index_information()
        index_keys = [tuple(idx["key"]) for idx in indexes.values()]
        assert (("release_id", 1), ("external_id", 1)) in index_keys
        assert (("stix_id", 1), ("release_id", 1)) in index_keys
