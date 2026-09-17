from __future__ import annotations

from loguru import logger
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError


class DriftDetector:
    def __init__(self, db: Database, secure_db: Database):
        self.db = db
        self.secure_db = secure_db

    def detect_impact(self, diff_doc: dict) -> list[dict]:
        diff_id = diff_doc["_id"]
        findings = []

        revoked_ids = [r["stix_id"] for r in diff_doc.get("revoked", [])]
        deprecated_ids = [d["stix_id"] for d in diff_doc.get("deprecated", [])]
        modified_ids = [m["stix_id"] for m in diff_doc.get("modified", []) if m.get("max_severity") != "low"]

        revoked_map = {r["stix_id"]: r for r in diff_doc.get("revoked", [])}
        deprecated_map = {d["stix_id"]: d for d in diff_doc.get("deprecated", [])}
        modified_map = {m["stix_id"]: m for m in diff_doc.get("modified", [])}

        all_affected_ids = list(set(revoked_ids + deprecated_ids + modified_ids))
        if not all_affected_ids:
            return findings

        try:
            affected_scenarios = self._query_affected_scenarios_lookup(all_affected_ids)
        except Exception:
            affected_scenarios = self._query_affected_scenarios(all_affected_ids)

        for hit in affected_scenarios:
            stix_id = hit["stix_id"]
            report_ids = hit.get("report_ids", [])

            if stix_id in revoked_map:
                info = revoked_map[stix_id]
                successors = info.get("successors", [])
                proposed = [
                    {
                        "stix_id": s["stix_id"],
                        "external_id": s.get("external_id"),
                        "basis": "revoked_by",
                        "confidence": 1.0,
                    }
                    for s in successors
                ]
                auto_eligible = len(successors) == 1
                finding_type = "technique_revoked"

            elif stix_id in deprecated_map:
                proposed = []
                auto_eligible = False
                finding_type = "technique_deprecated"

            elif stix_id in modified_map:
                proposed = []
                auto_eligible = False
                m_info = modified_map[stix_id]
                if "kill_chain_phases" in m_info.get("changed_paths", []):
                    finding_type = "tactic_moved"
                else:
                    finding_type = "technique_modified"

            else:
                continue

            finding = {
                "diff_id": diff_id,
                "scenario_id": hit["scenario_id"],
                "scenario_rev": hit["rev"],
                "step_id": hit["step_id"],
                "finding": finding_type,
                "from": {
                    "stix_id": stix_id,
                    "external_id": (
                        revoked_map.get(stix_id, {}).get("external_id")
                        or deprecated_map.get(stix_id, {}).get("external_id")
                        or modified_map.get(stix_id, {}).get("external_id")
                    ),
                },
                "proposed": proposed,
                "auto_remap_eligible": auto_eligible,
                "affected_reports": report_ids,
                "status": "open",
                "resolution": None,
            }
            findings.append(finding)

        inserted = self.upsert_findings(findings)
        logger.info(f"Drift detection for {diff_id}: {inserted} findings upserted from {len(findings)} candidates")
        return findings

    def _query_affected_scenarios_lookup(self, stix_ids: list[str]) -> list[dict]:
        pipeline = [
            {"$match": {"stix_id": {"$in": stix_ids}, "is_head": True}},
            {"$lookup": {
                "from": "reports",
                "let": {"sid": "$scenario_id", "rev": "$rev"},
                "pipeline": [
                    {"$match": {"$expr": {"$anyElementTrue": {
                        "$map": {
                            "input": "$manifest.scenario_set",
                            "as": "pin",
                            "in": {"$and": [
                                {"$eq": ["$$pin.scenario_id", "$$sid"]},
                                {"$eq": ["$$pin.rev", "$$rev"]},
                            ]},
                        },
                    }}}},
                    {"$project": {"_id": 1}},
                ],
                "as": "matched_reports",
            }},
            {"$project": {
                "scenario_id": 1,
                "rev": 1,
                "step_id": 1,
                "stix_id": 1,
                "report_ids": {
                    "$map": {"input": "$matched_reports", "as": "r", "in": "$$r._id"},
                },
            }},
        ]
        return list(self.secure_db.scenario_attack_refs.aggregate(pipeline))

    def _query_affected_scenarios(self, stix_ids: list[str]) -> list[dict]:
        refs = list(self.secure_db.scenario_attack_refs.find({
            "stix_id": {"$in": stix_ids},
            "is_head": True,
        }))

        results = []
        for ref in refs:
            report_ids = self._find_reports(ref["scenario_id"], ref["rev"])
            results.append({
                "scenario_id": ref["scenario_id"],
                "rev": ref["rev"],
                "step_id": ref["step_id"],
                "stix_id": ref["stix_id"],
                "report_ids": report_ids,
            })
        return results

    def _find_reports(self, scenario_id: str, rev: int) -> list[str]:
        reports = self.secure_db.reports.find(
            {"manifest.scenario_set": {"$elemMatch": {"scenario_id": scenario_id, "rev": rev}}},
            {"_id": 1},
        )
        return [r["_id"] for r in reports]

    def upsert_findings(self, findings: list[dict]) -> int:
        inserted = 0
        for finding in findings:
            try:
                self.secure_db.drift_findings.insert_one(finding)
                inserted += 1
            except DuplicateKeyError:
                pass
        return inserted
