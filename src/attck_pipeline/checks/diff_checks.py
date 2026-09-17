from __future__ import annotations

from attck_pipeline.checks.runner import CheckResult


def check_summary_matches_details(diff_doc: dict, **_) -> CheckResult:
    summary = diff_doc.get("summary", {})
    mismatches = {}

    for key in ("added", "revoked", "deprecated", "modified"):
        expected = summary.get(key, 0)
        actual = len(diff_doc.get(key, []))
        if expected != actual:
            mismatches[key] = {"summary": expected, "detail_count": actual}

    if not mismatches:
        return CheckResult(
            name="summary_matches_details",
            passed=True,
            severity="error",
            message="Summary counts match detail arrays",
        )
    return CheckResult(
        name="summary_matches_details",
        passed=False,
        severity="error",
        message=f"Summary/detail mismatch in {len(mismatches)} categories",
        details=mismatches,
    )


def check_revoked_have_successors(diff_doc: dict, **_) -> CheckResult:
    revoked = diff_doc.get("revoked", [])
    missing = [r for r in revoked if not r.get("successors")]

    if not missing:
        return CheckResult(
            name="revoked_have_successors",
            passed=True,
            severity="warning",
            message=f"All {len(revoked)} revoked techniques have successors listed",
        )
    return CheckResult(
        name="revoked_have_successors",
        passed=False,
        severity="warning",
        message=f"{len(missing)}/{len(revoked)} revoked techniques have no successors",
        details={"missing": [m.get("external_id", m["stix_id"]) for m in missing[:10]]},
    )
