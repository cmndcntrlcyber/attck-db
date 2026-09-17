from __future__ import annotations

from attck_pipeline.canonical import content_hash
from attck_pipeline.checks.runner import CheckResult


def check_no_quarantine_in_main_data(db, snapshot: dict, **_) -> CheckResult:
    quarantine_values = set()
    for q in db.ingest_quarantine.find({"source": "notion_overlay"}, {"value": 1}):
        quarantine_values.add(q["value"])

    if not quarantine_values:
        return CheckResult(
            name="no_quarantine_in_main_data",
            passed=True,
            severity="error",
            message="No quarantine items to check against",
        )

    leaked = []
    for row in snapshot.get("rows", []):
        for tag in row.get("tags", []):
            if tag.get("type") != "quarantine" and tag.get("value") in quarantine_values:
                leaked.append({"row": row.get("notion_page_id"), "tag": tag.get("value")})

    if not leaked:
        return CheckResult(
            name="no_quarantine_in_main_data",
            passed=True,
            severity="error",
            message=f"No quarantine items leaked into {len(snapshot.get('rows', []))} overlay rows",
        )
    return CheckResult(
        name="no_quarantine_in_main_data",
        passed=False,
        severity="error",
        message=f"{len(leaked)} quarantine items found in non-quarantine tags",
        details={"leaked": leaked[:10]},
    )


def check_snapshot_hash_verifiable(snapshot: dict, **_) -> CheckResult:
    rows = snapshot.get("rows", [])
    sorted_rows = sorted(rows, key=lambda r: r.get("notion_page_id", ""))
    recomputed = content_hash({"rows": sorted_rows})
    stored = snapshot.get("sha256", "")

    if recomputed == stored:
        return CheckResult(
            name="snapshot_hash_verifiable",
            passed=True,
            severity="error",
            message=f"Snapshot hash verified: {stored[:24]}...",
        )
    return CheckResult(
        name="snapshot_hash_verifiable",
        passed=False,
        severity="error",
        message=f"Snapshot hash mismatch: stored={stored[:24]}..., recomputed={recomputed[:24]}...",
        details={"stored": stored, "recomputed": recomputed},
    )
