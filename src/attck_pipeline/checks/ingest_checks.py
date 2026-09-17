from __future__ import annotations

import json

from attck_pipeline.checks.runner import CheckResult

SKIPPED_STIX_TYPES = {"identity", "marking-definition", "relationship"}


def check_object_count_matches_bundle(db, release_id: str, raw_bundle: bytes, **_) -> CheckResult:
    bundle = json.loads(raw_bundle)
    expected = sum(1 for o in bundle.get("objects", []) if o.get("type") not in SKIPPED_STIX_TYPES)
    actual = db.release_members.count_documents({"release_id": release_id})

    if actual == expected:
        return CheckResult(
            name="object_count_matches_bundle",
            passed=True,
            severity="error",
            message=f"Object count matches: {actual}",
        )
    return CheckResult(
        name="object_count_matches_bundle",
        passed=False,
        severity="error",
        message=f"Expected {expected} objects from bundle, found {actual} release members",
        details={"expected": expected, "actual": actual},
    )


def check_no_duplicate_stix_ids_in_release(db, release_id: str, **_) -> CheckResult:
    pipeline = [
        {"$match": {"release_id": release_id}},
        {"$group": {"_id": "$stix_id", "count": {"$sum": 1}}},
        {"$match": {"count": {"$gt": 1}}},
    ]
    try:
        duplicates = list(db.release_members.aggregate(pipeline))
    except Exception:
        seen = {}
        for m in db.release_members.find({"release_id": release_id}, {"stix_id": 1}):
            sid = m["stix_id"]
            seen[sid] = seen.get(sid, 0) + 1
        duplicates = [{"_id": k, "count": v} for k, v in seen.items() if v > 1]

    if not duplicates:
        return CheckResult(
            name="no_duplicate_stix_ids_in_release",
            passed=True,
            severity="error",
            message="No duplicate STIX IDs in release",
        )
    return CheckResult(
        name="no_duplicate_stix_ids_in_release",
        passed=False,
        severity="error",
        message=f"Found {len(duplicates)} duplicate STIX IDs in release",
        details={"duplicates": [d["_id"] for d in duplicates[:10]]},
    )


def check_techniques_have_tactic_shortnames(db, release_id: str, **_) -> CheckResult:
    members = list(db.release_members.find({"release_id": release_id}, {"object_hash": 1}))
    hashes = [m["object_hash"] for m in members]

    missing = list(db.attack_objects.find({
        "_id": {"$in": hashes},
        "kind": {"$in": ["technique", "subtechnique"]},
        "$or": [
            {"tactic_shortnames": None},
            {"tactic_shortnames": []},
        ],
    }, {"stix_id": 1, "external_id": 1, "name": 1}))

    if not missing:
        return CheckResult(
            name="techniques_have_tactic_shortnames",
            passed=True,
            severity="warning",
            message="All techniques have tactic_shortnames",
        )
    return CheckResult(
        name="techniques_have_tactic_shortnames",
        passed=False,
        severity="warning",
        message=f"{len(missing)} techniques missing tactic_shortnames",
        details={"missing": [m.get("external_id", m["stix_id"]) for m in missing[:10]]},
    )
