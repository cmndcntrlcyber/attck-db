from __future__ import annotations

from datetime import datetime, timezone

from loguru import logger
from pymongo import MongoClient
from pymongo.database import Database

from attck_pipeline.db.txn import transaction
from attck_pipeline.diff.classify import classify_modification


class DiffEngine:
    def __init__(self, db: Database):
        self.db = db

    def compute_diff(self, from_release: str, to_release: str) -> dict:
        diff_id = f"{from_release}..{to_release}"

        existing = self.db.release_diffs.find_one({"_id": diff_id})
        if existing:
            logger.info(f"Diff {diff_id} already exists, returning cached")
            return existing

        pipeline = [
            {"$match": {"release_id": {"$in": [from_release, to_release]}}},
            {"$group": {
                "_id": "$stix_id",
                "states": {"$push": {
                    "r": "$release_id",
                    "h": "$object_hash",
                    "state": "$state",
                    "xid": "$external_id",
                }},
            }},
            {"$project": {
                "old": {"$first": {"$filter": {
                    "input": "$states",
                    "cond": {"$eq": ["$$this.r", from_release]},
                }}},
                "new": {"$first": {"$filter": {
                    "input": "$states",
                    "cond": {"$eq": ["$$this.r", to_release]},
                }}},
            }},
            {"$addFields": {"change": {"$switch": {"branches": [
                {"case": {"$not": ["$old"]}, "then": "added"},
                {"case": {"$and": [
                    {"$eq": ["$old.state", "active"]},
                    {"$eq": ["$new.state", "revoked"]},
                ]}, "then": "revoked"},
                {"case": {"$and": [
                    {"$eq": ["$old.state", "active"]},
                    {"$eq": ["$new.state", "deprecated"]},
                ]}, "then": "deprecated"},
                {"case": {"$ne": ["$old.h", "$new.h"]}, "then": "modified"},
            ], "default": "unchanged"}}}},
        ]

        try:
            results = list(self.db.release_members.aggregate(pipeline))
        except Exception:
            results = self._python_diff(from_release, to_release)

        added = []
        revoked = []
        deprecated = []
        modified = []
        unchanged_count = 0

        for row in results:
            change = row["change"]
            stix_id = row["_id"]

            if change == "added":
                new_info = row.get("new", {})
                added.append({
                    "stix_id": stix_id,
                    "external_id": new_info.get("xid") if new_info else None,
                })

            elif change == "revoked":
                old_info = row.get("old", {})
                successors = self._find_successors(to_release, stix_id)
                revoked.append({
                    "stix_id": stix_id,
                    "external_id": old_info.get("xid") if old_info else None,
                    "successors": successors,
                })

            elif change == "deprecated":
                old_info = row.get("old", {})
                deprecated.append({
                    "stix_id": stix_id,
                    "external_id": old_info.get("xid") if old_info else None,
                })

            elif change == "modified":
                old_info = row.get("old", {})
                new_info = row.get("new", {})
                detail = self._classify_change(
                    old_info.get("h") if old_info else None,
                    new_info.get("h") if new_info else None,
                    stix_id,
                    old_info.get("xid") if old_info else None,
                )
                modified.append({
                    "stix_id": stix_id,
                    "external_id": old_info.get("xid") if old_info else None,
                    "changed_paths": detail.changed_paths if detail else [],
                    "max_severity": detail.max_severity if detail else "low",
                })

            else:
                unchanged_count += 1

        diff_doc = {
            "_id": diff_id,
            "from": from_release,
            "to": to_release,
            "algo_version": "diff/1.0",
            "summary": {
                "added": len(added),
                "revoked": len(revoked),
                "deprecated": len(deprecated),
                "modified": len(modified),
                "unchanged": unchanged_count,
            },
            "revoked": revoked,
            "deprecated": deprecated,
            "added": added,
            "modified": modified,
            "computed_at": datetime.now(timezone.utc),
        }

        logger.info(
            f"Diff {diff_id}: {len(added)} added, {len(revoked)} revoked, "
            f"{len(deprecated)} deprecated, {len(modified)} modified, {unchanged_count} unchanged"
        )

        return diff_doc

    def seal_release(self, client: MongoClient, to_release: str, diff_doc: dict) -> None:
        try:
            with transaction(client) as session:
                self.db.release_diffs.insert_one(diff_doc, session=session)
                self.db.framework_releases.update_one(
                    {"_id": to_release, "status": "staging"},
                    {"$set": {"status": "sealed"}},
                    session=session,
                )
        except Exception:
            self.db.release_diffs.update_one(
                {"_id": diff_doc["_id"]},
                {"$setOnInsert": diff_doc},
                upsert=True,
            )
            self.db.framework_releases.update_one(
                {"_id": to_release, "status": "staging"},
                {"$set": {"status": "sealed"}},
            )
        logger.info(f"Sealed release {to_release}")

    def _find_successors(self, release_id: str, stix_id: str) -> list[dict]:
        edges = self.db.identity_edges.find({
            "release_id": release_id,
            "kind": "revoked_by",
            "from.stix_id": stix_id,
        })
        successors = []
        for edge in edges:
            to = edge.get("to", {})
            if to:
                successors.append({
                    "stix_id": to["stix_id"],
                    "external_id": to.get("external_id"),
                })
        return successors

    def _classify_change(
        self, old_hash: str | None, new_hash: str | None, stix_id: str, external_id: str | None
    ):
        if not old_hash or not new_hash:
            return None

        old_obj = self.db.attack_objects.find_one({"_id": old_hash})
        new_obj = self.db.attack_objects.find_one({"_id": new_hash})

        if not old_obj or not new_obj:
            return None

        return classify_modification(old_obj["raw"], new_obj["raw"], stix_id, external_id)

    def _python_diff(self, from_release: str, to_release: str) -> list[dict]:
        """Python-side fallback when the aggregation pipeline isn't supported."""
        from_members = {
            m["stix_id"]: m
            for m in self.db.release_members.find({"release_id": from_release})
        }
        to_members = {
            m["stix_id"]: m
            for m in self.db.release_members.find({"release_id": to_release})
        }

        all_ids = set(from_members) | set(to_members)
        results = []
        for stix_id in all_ids:
            old = from_members.get(stix_id)
            new = to_members.get(stix_id)

            if not old:
                change = "added"
            elif old and new and old["state"] == "active" and new["state"] == "revoked":
                change = "revoked"
            elif old and new and old["state"] == "active" and new["state"] == "deprecated":
                change = "deprecated"
            elif old and new and old["object_hash"] != new["object_hash"]:
                change = "modified"
            else:
                change = "unchanged"

            results.append({
                "_id": stix_id,
                "old": {"r": from_release, "h": old["object_hash"], "state": old["state"], "xid": old.get("external_id")} if old else None,
                "new": {"r": to_release, "h": new["object_hash"], "state": new["state"], "xid": new.get("external_id")} if new else None,
                "change": change,
            })
        return results
