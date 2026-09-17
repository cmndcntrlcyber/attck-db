from __future__ import annotations

from attck_pipeline.checks.runner import CheckResult


def check_revoked_objects_have_edges(db, release_id: str, **_) -> CheckResult:
    revoked = list(db.release_members.find(
        {"release_id": release_id, "state": "revoked"},
        {"stix_id": 1},
    ))

    missing = []
    for member in revoked:
        edge = db.identity_edges.find_one({
            "release_id": release_id,
            "from.stix_id": member["stix_id"],
        })
        if not edge:
            missing.append(member["stix_id"])

    if not missing:
        return CheckResult(
            name="revoked_objects_have_edges",
            passed=True,
            severity="error",
            message=f"All {len(revoked)} revoked objects have lineage edges",
        )
    return CheckResult(
        name="revoked_objects_have_edges",
        passed=False,
        severity="error",
        message=f"{len(missing)}/{len(revoked)} revoked objects have no lineage edge",
        details={"missing": missing[:10]},
    )


def check_no_orphan_edges(db, release_id: str, **_) -> CheckResult:
    edges = list(db.identity_edges.find({"release_id": release_id}))

    orphans = []
    for edge in edges:
        from_sid = edge["from"]["stix_id"]
        from_member = db.release_members.find_one({
            "release_id": release_id,
            "stix_id": from_sid,
        })
        if not from_member:
            orphans.append(f"from:{from_sid}")
            continue

        to_info = edge.get("to")
        if to_info and to_info.get("stix_id"):
            to_member = db.release_members.find_one({
                "release_id": release_id,
                "stix_id": to_info["stix_id"],
            })
            if not to_member:
                orphans.append(f"to:{to_info['stix_id']}")

    if not orphans:
        return CheckResult(
            name="no_orphan_edges",
            passed=True,
            severity="warning",
            message=f"All {len(edges)} edges reference valid release members",
        )
    return CheckResult(
        name="no_orphan_edges",
        passed=False,
        severity="warning",
        message=f"{len(orphans)} orphan edge endpoints found",
        details={"orphans": orphans[:10]},
    )
