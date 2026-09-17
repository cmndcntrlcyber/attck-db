from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from loguru import logger
from pymongo.database import Database

from attck_pipeline.canonical import bundle_hash, content_hash
from attck_pipeline.models.stix import determine_state, extract_external_id, stix_to_attack_object


class StixLoader:
    def __init__(self, db: Database, storage=None):
        self.db = db
        self.storage = storage

    def load_release(
        self,
        domain: str,
        version: str,
        raw_bytes: bytes,
        source_uri: str,
        git_ref: str = "",
        released_at: datetime | None = None,
        predecessor: str | None = None,
    ) -> tuple[str, list[dict]]:
        release_id = f"{domain}@{version}"
        sha256 = bundle_hash(raw_bytes)
        run_id = f"run-{uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)

        existing = self.db.framework_releases.find_one({"_id": release_id})
        if existing and existing.get("status") == "sealed":
            logger.info(f"Release {release_id} already sealed, skipping")
            return run_id, []

        bundle = json.loads(raw_bytes)
        stix_objects = bundle.get("objects", [])

        blob_ref = None
        if self.storage:
            stored = self.storage.put_bundle(domain, version, raw_bytes, sha256)
            blob_ref = self.storage.blob_ref(stored.bucket, stored.key)

        if not existing:
            self.db.framework_releases.insert_one({
                "_id": release_id,
                "domain": domain,
                "version": version,
                "predecessor": predecessor,
                "released_at": released_at or now,
                "source": {
                    "uri": source_uri,
                    "git_ref": git_ref,
                    "sha256": sha256,
                    "blob_ref": blob_ref,
                },
                "counts": {},
                "ingest_run_id": run_id,
                "ingested_at": now,
                "status": "staging",
            })

        self.db.ingest_runs.insert_one({
            "_id": run_id,
            "release_id": release_id,
            "status": "running",
            "started_at": now,
            "completed_at": None,
            "counts": {},
            "duration_ms": None,
            "error": None,
        })

        relationships = []
        counts: dict[str, int] = {}
        objects_inserted = 0
        members_inserted = 0

        for stix_obj in stix_objects:
            stix_type = stix_obj.get("type", "")

            if stix_type == "relationship":
                relationships.append(stix_obj)
                continue

            attack_obj = stix_to_attack_object(stix_obj)
            if attack_obj is None:
                continue

            kind = attack_obj["kind"]
            counts[kind] = counts.get(kind, 0) + 1

            result = self.db.attack_objects.update_one(
                {"_id": attack_obj["_id"]},
                {"$setOnInsert": attack_obj},
                upsert=True,
            )
            if result.upserted_id:
                objects_inserted += 1

            member_id = {"r": release_id, "s": stix_obj["id"]}
            state = determine_state(stix_obj)
            external_id = extract_external_id(stix_obj)

            self.db.release_members.update_one(
                {"_id": member_id},
                {"$setOnInsert": {
                    "_id": member_id,
                    "release_id": release_id,
                    "stix_id": stix_obj["id"],
                    "external_id": external_id,
                    "object_hash": attack_obj["_id"],
                    "state": state,
                }},
                upsert=True,
            )
            members_inserted += 1

        self.db.framework_releases.update_one(
            {"_id": release_id},
            {"$set": {"counts": counts}},
        )

        elapsed = (datetime.now(timezone.utc) - now).total_seconds() * 1000
        self.db.ingest_runs.update_one(
            {"_id": run_id},
            {"$set": {
                "status": "completed",
                "completed_at": datetime.now(timezone.utc),
                "counts": {
                    "objects_inserted": objects_inserted,
                    "members_inserted": members_inserted,
                    "relationships_collected": len(relationships),
                    **{f"kind_{k}": v for k, v in counts.items()},
                },
                "duration_ms": int(elapsed),
            }},
        )

        logger.info(
            f"Loaded {release_id}: {objects_inserted} objects, {members_inserted} members, "
            f"{len(relationships)} relationships"
        )

        return run_id, relationships
