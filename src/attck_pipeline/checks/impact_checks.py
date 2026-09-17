from __future__ import annotations

from attck_pipeline.checks.runner import CheckResult


def check_findings_count_matches_affected(secure_db, diff_doc: dict, findings: list[dict], **_) -> CheckResult:
    revoked_ids = [r["stix_id"] for r in diff_doc.get("revoked", [])]
    deprecated_ids = [d["stix_id"] for d in diff_doc.get("deprecated", [])]
    modified_ids = [m["stix_id"] for m in diff_doc.get("modified", []) if m.get("max_severity") != "low"]
    all_ids = list(set(revoked_ids + deprecated_ids + modified_ids))

    if not all_ids:
        if not findings:
            return CheckResult(
                name="findings_count_matches_affected",
                passed=True,
                severity="error",
                message="No affected techniques and no findings — correct",
            )

    affected_refs = list(secure_db.scenario_attack_refs.find({
        "stix_id": {"$in": all_ids},
        "is_head": True,
    }))
    expected = len(affected_refs)
    actual = len(findings)

    if actual == expected:
        return CheckResult(
            name="findings_count_matches_affected",
            passed=True,
            severity="error",
            message=f"Findings count matches affected scenario steps: {actual}",
        )
    return CheckResult(
        name="findings_count_matches_affected",
        passed=False,
        severity="error",
        message=f"Expected {expected} findings from affected refs, got {actual}",
        details={"expected": expected, "actual": actual},
    )


def check_findings_have_valid_status(findings: list[dict], **_) -> CheckResult:
    invalid = [f for f in findings if f.get("status") != "open"]

    if not invalid:
        return CheckResult(
            name="findings_have_valid_status",
            passed=True,
            severity="error",
            message=f"All {len(findings)} findings have status 'open'",
        )
    return CheckResult(
        name="findings_have_valid_status",
        passed=False,
        severity="error",
        message=f"{len(invalid)}/{len(findings)} findings have unexpected status",
        details={"invalid_statuses": list({f.get("status") for f in invalid})},
    )
