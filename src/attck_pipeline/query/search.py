from __future__ import annotations

import re

from pymongo.database import Database


class TechniqueSearch:
    def __init__(self, db: Database):
        self.db = db

    def search(
        self,
        query: str,
        kind: str | None = None,
        release_id: str | None = None,
        limit: int = 20,
    ) -> list[dict]:
        match_filter: dict = {}
        if kind:
            match_filter["kind"] = kind

        try:
            return self._text_search(query, match_filter, limit, release_id)
        except Exception:
            return self._regex_search(query, match_filter, limit, release_id)

    def _text_search(
        self, query: str, match_filter: dict, limit: int, release_id: str | None,
    ) -> list[dict]:
        pipeline: list[dict] = [
            {"$match": {**match_filter, "$text": {"$search": query}}},
            {"$addFields": {"score": {"$meta": "textScore"}}},
        ]

        if release_id:
            pipeline.append({
                "$lookup": {
                    "from": "release_members",
                    "let": {"sid": "$stix_id"},
                    "pipeline": [
                        {"$match": {"$expr": {"$and": [
                            {"$eq": ["$release_id", release_id]},
                            {"$eq": ["$stix_id", "$$sid"]},
                            {"$eq": ["$state", "active"]},
                        ]}}},
                    ],
                    "as": "membership",
                },
            })
            pipeline.append({"$match": {"membership": {"$ne": []}}})

        pipeline.extend([
            {"$sort": {"score": -1}},
            {"$limit": limit},
            {"$project": {
                "stix_id": 1,
                "kind": 1,
                "name": 1,
                "external_id": 1,
                "description": {"$substrCP": ["$description", 0, 200]},
                "score": 1,
                "revoked": 1,
                "deprecated": 1,
            }},
        ])
        return list(self.db.attack_objects.aggregate(pipeline))

    def _regex_search(
        self, query: str, match_filter: dict, limit: int, release_id: str | None,
    ) -> list[dict]:
        pattern = re.compile(re.escape(query), re.IGNORECASE)
        filter_doc = {
            **match_filter,
            "$or": [
                {"name": {"$regex": pattern}},
                {"description": {"$regex": pattern}},
            ],
        }
        results = list(self.db.attack_objects.find(
            filter_doc,
            {"stix_id": 1, "kind": 1, "name": 1, "external_id": 1,
             "description": 1, "revoked": 1, "deprecated": 1},
        ).limit(limit))

        if release_id:
            results = [
                r for r in results
                if self.db.release_members.find_one({
                    "release_id": release_id,
                    "stix_id": r["stix_id"],
                    "state": "active",
                })
            ]

        return results

    def search_overlay(self, query: str, limit: int = 20) -> list[dict]:
        snapshot = self.db.overlay_snapshots.find_one(
            {"recorded_to": None},
            sort=[("captured_at", -1)],
        )
        if not snapshot:
            return []

        pattern = re.compile(re.escape(query), re.IGNORECASE)
        matches = []
        for row in snapshot.get("rows", []):
            if pattern.search(row.get("name", "")):
                matches.append(row)
                if len(matches) >= limit:
                    break
        return matches
