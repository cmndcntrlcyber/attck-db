from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone

from loguru import logger
from pymongo import MongoClient
from pymongo.database import Database

from attck_pipeline.scenarios.revisions import ScenarioRevisionManager


@dataclass
class RemapResult:
    scenario_id: str
    old_rev: int
    new_rev: int
    finding_id: object
    success: bool = True
    error: str | None = None


@dataclass
class BulkRemapResult:
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    results: list[RemapResult] = field(default_factory=list)


class RemapEngine:
    def __init__(self, db: Database, secure_db: Database):
        self.db = db
        self.secure_db = secure_db
        self.revision_mgr = ScenarioRevisionManager(secure_db)

    def accept_finding(
        self,
        client: MongoClient,
        finding_id: object,
        actor: str = "auto-remap",
    ) -> RemapResult:
        finding = self.secure_db.drift_findings.find_one({"_id": finding_id})
        if not finding:
            return RemapResult(
                scenario_id="", old_rev=0, new_rev=0, finding_id=finding_id,
                success=False, error="Finding not found",
            )

        if finding["status"] != "open":
            return RemapResult(
                scenario_id=finding["scenario_id"],
                old_rev=finding["scenario_rev"],
                new_rev=0,
                finding_id=finding_id,
                success=False,
                error=f"Finding status is '{finding['status']}', expected 'open'",
            )

        if not finding.get("auto_remap_eligible"):
            return RemapResult(
                scenario_id=finding["scenario_id"],
                old_rev=finding["scenario_rev"],
                new_rev=0,
                finding_id=finding_id,
                success=False,
                error="Finding is not auto-remap eligible",
            )

        proposed = finding.get("proposed", [])
        if len(proposed) != 1:
            return RemapResult(
                scenario_id=finding["scenario_id"],
                old_rev=finding["scenario_rev"],
                new_rev=0,
                finding_id=finding_id,
                success=False,
                error=f"Expected exactly 1 proposed successor, got {len(proposed)}",
            )

        successor = proposed[0]
        scenario_id = finding["scenario_id"]
        step_id = finding["step_id"]
        from_stix_id = finding["from"]["stix_id"]
        diff_id = finding["diff_id"]

        to_release = diff_id.split("..")[-1] if ".." in diff_id else None
        if not to_release:
            return RemapResult(
                scenario_id=scenario_id, old_rev=finding["scenario_rev"],
                new_rev=0, finding_id=finding_id,
                success=False, error="Cannot parse to_release from diff_id",
            )

        current_head = self.secure_db.scenarios.find_one(
            {"scenario_id": scenario_id, "is_head": True},
        )
        if not current_head:
            return RemapResult(
                scenario_id=scenario_id, old_rev=finding["scenario_rev"],
                new_rev=0, finding_id=finding_id,
                success=False, error="No head revision found",
            )

        new_steps = copy.deepcopy(current_head["steps"])
        remapped = False
        for step in new_steps:
            if step.get("step_id") == step_id:
                attack_ref = step.get("attack_ref", {})
                if attack_ref.get("stix_id") == from_stix_id:
                    step["attack_ref"] = {
                        "stix_id": successor["stix_id"],
                        "external_id_at_pin": successor.get("external_id"),
                        "release_id": to_release,
                    }
                    remapped = True
                    break

        if not remapped:
            return RemapResult(
                scenario_id=scenario_id, old_rev=current_head["rev"],
                new_rev=0, finding_id=finding_id,
                success=False, error=f"Step {step_id} with stix_id {from_stix_id} not found",
            )

        new_rev = self.revision_mgr.create_revision(
            scenario_id=scenario_id,
            new_steps=new_steps,
            new_framework_pin=to_release,
            created_by=actor,
        )

        now = datetime.now(timezone.utc)
        self.secure_db.drift_findings.update_one(
            {"_id": finding_id},
            {"$set": {
                "status": "accepted",
                "resolution": {
                    "by": actor,
                    "at": now,
                    "choice": "auto_remap",
                    "new_scenario_rev": new_rev,
                },
            }},
        )

        logger.info(f"Remapped {scenario_id} rev {current_head['rev']} -> {new_rev}")
        return RemapResult(
            scenario_id=scenario_id,
            old_rev=current_head["rev"],
            new_rev=new_rev,
            finding_id=finding_id,
        )

    def bulk_auto_remap(self, client: MongoClient, diff_id: str) -> BulkRemapResult:
        findings = list(self.secure_db.drift_findings.find({
            "diff_id": diff_id,
            "auto_remap_eligible": True,
            "status": "open",
        }))

        result = BulkRemapResult(total=len(findings))

        for finding in findings:
            remap_result = self.accept_finding(client, finding["_id"])
            result.results.append(remap_result)
            if remap_result.success:
                result.succeeded += 1
            else:
                result.failed += 1

        logger.info(
            f"Bulk remap for {diff_id}: {result.succeeded}/{result.total} succeeded, "
            f"{result.failed} failed"
        )
        return result
