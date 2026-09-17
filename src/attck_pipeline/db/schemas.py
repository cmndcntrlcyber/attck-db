def framework_releases_schema() -> dict:
    return {
        "bsonType": "object",
        "required": ["_id", "domain", "version", "source", "status", "ingested_at"],
        "properties": {
            "_id": {"bsonType": "string"},
            "domain": {"bsonType": "string"},
            "version": {"bsonType": "string"},
            "predecessor": {"bsonType": ["string", "null"]},
            "released_at": {"bsonType": "date"},
            "source": {
                "bsonType": "object",
                "required": ["uri", "sha256"],
                "properties": {
                    "uri": {"bsonType": "string"},
                    "git_ref": {"bsonType": "string"},
                    "sha256": {"bsonType": "string"},
                    "blob_ref": {"bsonType": ["string", "null"]},
                },
            },
            "counts": {"bsonType": "object"},
            "ingest_run_id": {"bsonType": "string"},
            "ingested_at": {"bsonType": "date"},
            "status": {"enum": ["staging", "sealed"]},
        },
    }


def attack_objects_schema() -> dict:
    base_props = {
        "_id": {"bsonType": "string"},
        "stix_id": {"bsonType": "string"},
        "stix_type": {"bsonType": "string"},
        "kind": {"bsonType": "string"},
        "external_id": {"bsonType": ["string", "null"]},
        "name": {"bsonType": "string"},
        "modified": {"bsonType": "string"},
        "x_mitre_version": {"bsonType": ["string", "null"]},
        "revoked": {"bsonType": "bool"},
        "deprecated": {"bsonType": "bool"},
        "parent_stix_id": {"bsonType": ["string", "null"]},
        "tactic_shortnames": {
            "bsonType": ["array", "null"],
            "items": {"bsonType": "string"},
        },
        "platforms": {
            "bsonType": ["array", "null"],
            "items": {"bsonType": "string"},
        },
        "description": {"bsonType": ["string", "null"]},
        "raw": {"bsonType": "object"},
    }

    tactic_extra = {
        "x_mitre_shortname": {"bsonType": "string"},
    }

    return {
        "bsonType": "object",
        "required": [
            "_id",
            "stix_id",
            "stix_type",
            "kind",
            "name",
            "modified",
            "revoked",
            "deprecated",
            "raw",
        ],
        "properties": {**base_props, **tactic_extra},
        "oneOf": [
            {
                "properties": {"kind": {"enum": ["tactic"]}},
                "required": ["x_mitre_shortname"],
            },
            {
                "properties": {"kind": {"enum": ["technique"]}},
                "required": ["tactic_shortnames", "platforms"],
            },
            {
                "properties": {"kind": {"enum": ["subtechnique"]}},
                "required": ["tactic_shortnames", "platforms"],
            },
            {
                "properties": {"kind": {"enum": ["group"]}},
            },
            {
                "properties": {"kind": {"enum": ["software"]}},
            },
            {
                "properties": {"kind": {"enum": ["mitigation"]}},
            },
            {
                "properties": {"kind": {"enum": ["procedure"]}},
            },
            {
                "properties": {"kind": {"enum": ["datasource"]}},
            },
            {
                "properties": {"kind": {"enum": ["datacomponent"]}},
            },
            {
                "properties": {"kind": {"enum": ["campaign"]}},
            },
            {
                "properties": {"kind": {"enum": ["matrix"]}},
            },
            {
                "properties": {"kind": {"enum": ["collection"]}},
            },
            {
                "properties": {"kind": {"enum": ["custom"]}},
            },
        ],
    }


def release_members_schema() -> dict:
    return {
        "bsonType": "object",
        "required": ["_id", "release_id", "stix_id", "object_hash", "state"],
        "properties": {
            "_id": {
                "bsonType": "object",
                "required": ["r", "s"],
                "properties": {
                    "r": {"bsonType": "string"},
                    "s": {"bsonType": "string"},
                },
            },
            "release_id": {"bsonType": "string"},
            "stix_id": {"bsonType": "string"},
            "external_id": {"bsonType": ["string", "null"]},
            "object_hash": {"bsonType": "string"},
            "state": {"enum": ["active", "revoked", "deprecated"]},
        },
    }


def identity_edges_schema() -> dict:
    return {
        "bsonType": "object",
        "required": ["release_id", "kind", "from", "evidence", "confidence"],
        "properties": {
            "release_id": {"bsonType": "string"},
            "kind": {
                "enum": [
                    "revoked_by",
                    "subtechnique_of",
                    "deprecated_no_successor",
                    "split_into",
                    "merged_into",
                ]
            },
            "from": {
                "bsonType": "object",
                "required": ["stix_id"],
                "properties": {
                    "stix_id": {"bsonType": "string"},
                    "external_id": {"bsonType": ["string", "null"]},
                },
            },
            "to": {
                "bsonType": ["object", "null"],
                "properties": {
                    "stix_id": {"bsonType": "string"},
                    "external_id": {"bsonType": ["string", "null"]},
                },
            },
            "evidence": {"bsonType": "object"},
            "confidence": {"bsonType": "double"},
        },
    }


def release_diffs_schema() -> dict:
    return {
        "bsonType": "object",
        "required": ["_id", "from", "to", "algo_version", "summary", "computed_at"],
        "properties": {
            "_id": {"bsonType": "string"},
            "from": {"bsonType": "string"},
            "to": {"bsonType": "string"},
            "algo_version": {"bsonType": "string"},
            "summary": {
                "bsonType": "object",
                "required": ["added", "revoked", "deprecated", "modified", "unchanged"],
                "properties": {
                    "added": {"bsonType": "int"},
                    "revoked": {"bsonType": "int"},
                    "deprecated": {"bsonType": "int"},
                    "modified": {"bsonType": "int"},
                    "unchanged": {"bsonType": "int"},
                },
            },
            "revoked": {"bsonType": "array"},
            "deprecated": {"bsonType": "array"},
            "added": {"bsonType": "array"},
            "modified": {"bsonType": "array"},
            "computed_at": {"bsonType": "date"},
        },
    }


def scenarios_schema() -> dict:
    return {
        "bsonType": "object",
        "required": [
            "_id",
            "scenario_id",
            "rev",
            "is_head",
            "framework_pin",
            "content_hash",
            "steps",
            "created_at",
            "created_by",
        ],
        "properties": {
            "_id": {
                "bsonType": "object",
                "required": ["scenario_id", "rev"],
                "properties": {
                    "scenario_id": {"bsonType": "string"},
                    "rev": {"bsonType": "int"},
                },
            },
            "scenario_id": {"bsonType": "string"},
            "rev": {"bsonType": "int"},
            "is_head": {"bsonType": "bool"},
            "framework_pin": {"bsonType": "string"},
            "content_hash": {"bsonType": "string"},
            "steps": {"bsonType": "array"},
            "classification": {"bsonType": "object"},
            "created_at": {"bsonType": "date"},
            "created_by": {"bsonType": "string"},
            "recorded_from": {"bsonType": "date"},
            "recorded_to": {"bsonType": ["date", "null"]},
        },
    }


def scenario_attack_refs_schema() -> dict:
    return {
        "bsonType": "object",
        "required": ["scenario_id", "rev", "is_head", "step_id", "stix_id", "release_id"],
        "properties": {
            "scenario_id": {"bsonType": "string"},
            "rev": {"bsonType": "int"},
            "is_head": {"bsonType": "bool"},
            "step_id": {"bsonType": "string"},
            "stix_id": {"bsonType": "string"},
            "release_id": {"bsonType": "string"},
        },
    }


def drift_findings_schema() -> dict:
    return {
        "bsonType": "object",
        "required": ["diff_id", "scenario_id", "scenario_rev", "step_id", "finding", "status"],
        "properties": {
            "diff_id": {"bsonType": "string"},
            "scenario_id": {"bsonType": "string"},
            "scenario_rev": {"bsonType": "int"},
            "step_id": {"bsonType": "string"},
            "finding": {
                "enum": [
                    "technique_revoked",
                    "technique_deprecated",
                    "technique_modified",
                    "tactic_moved",
                ]
            },
            "from": {"bsonType": "object"},
            "proposed": {"bsonType": "array"},
            "auto_remap_eligible": {"bsonType": "bool"},
            "affected_reports": {"bsonType": "array"},
            "status": {"enum": ["open", "accepted", "overridden", "dismissed"]},
            "resolution": {"bsonType": ["object", "null"]},
        },
    }


def reports_schema() -> dict:
    return {
        "bsonType": "object",
        "required": ["_id", "period", "manifest", "manifest_sha256", "generated_at"],
        "properties": {
            "_id": {"bsonType": "string"},
            "period": {
                "bsonType": "object",
                "required": ["from", "to"],
                "properties": {
                    "from": {"bsonType": "date"},
                    "to": {"bsonType": "date"},
                },
            },
            "manifest": {"bsonType": "object"},
            "manifest_sha256": {"bsonType": "string"},
            "output": {"bsonType": ["object", "null"]},
            "generated_at": {"bsonType": "date"},
        },
    }


def overlay_snapshots_schema() -> dict:
    return {
        "bsonType": "object",
        "required": ["_id", "sha256", "captured_at", "recorded_from"],
        "properties": {
            "_id": {"bsonType": "string"},
            "sha256": {"bsonType": "string"},
            "rows": {"bsonType": "array"},
            "captured_at": {"bsonType": "date"},
            "recorded_from": {"bsonType": "date"},
            "recorded_to": {"bsonType": ["date", "null"]},
        },
    }


def ingest_quarantine_schema() -> dict:
    return {
        "bsonType": "object",
        "required": ["value", "source", "reason"],
        "properties": {
            "value": {"bsonType": "string"},
            "source": {"bsonType": "string"},
            "reason": {"bsonType": "string"},
            "suggested_fix": {"bsonType": ["string", "null"]},
            "created_at": {"bsonType": "date"},
        },
    }


def ingest_runs_schema() -> dict:
    return {
        "bsonType": "object",
        "required": ["_id", "release_id", "status", "started_at"],
        "properties": {
            "_id": {"bsonType": "string"},
            "release_id": {"bsonType": "string"},
            "status": {"enum": ["running", "completed", "failed"]},
            "started_at": {"bsonType": "date"},
            "completed_at": {"bsonType": ["date", "null"]},
            "counts": {"bsonType": "object"},
            "duration_ms": {"bsonType": ["int", "null"]},
            "error": {"bsonType": ["string", "null"]},
        },
    }
