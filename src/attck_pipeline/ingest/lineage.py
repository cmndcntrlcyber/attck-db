from __future__ import annotations

from loguru import logger
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError


class LineageBuilder:
    def __init__(self, db: Database):
        self.db = db

    def build_edges(self, release_id: str, stix_objects: list[dict]) -> int:
        relationships = [o for o in stix_objects if o.get("type") == "relationship"]
        all_objects = [o for o in stix_objects if o.get("type") != "relationship"]

        edges_inserted = 0
        revoked_by_sources: set[str] = set()

        for rel in relationships:
            rel_type = rel.get("relationship_type", "")
            source_ref = rel.get("source_ref", "")
            target_ref = rel.get("target_ref", "")

            if rel_type == "revoked-by":
                revoked_by_sources.add(source_ref)
                edge = self._make_edge(
                    release_id=release_id,
                    kind="revoked_by",
                    from_stix_id=source_ref,
                    to_stix_id=target_ref,
                    evidence={
                        "source": "mitre_bundle",
                        "stix_relationship_id": rel["id"],
                    },
                )
                if self._upsert_edge(edge):
                    edges_inserted += 1

            elif rel_type == "subtechnique-of":
                edge = self._make_edge(
                    release_id=release_id,
                    kind="subtechnique_of",
                    from_stix_id=source_ref,
                    to_stix_id=target_ref,
                    evidence={
                        "source": "mitre_bundle",
                        "stix_relationship_id": rel["id"],
                    },
                )
                if self._upsert_edge(edge):
                    edges_inserted += 1

                self.db.attack_objects.update_many(
                    {"stix_id": source_ref, "parent_stix_id": None},
                    {"$set": {"parent_stix_id": target_ref}},
                )

        for obj in all_objects:
            if obj.get("x_mitre_deprecated", False) and obj["id"] not in revoked_by_sources:
                if obj.get("type") in ("attack-pattern", "malware", "tool", "intrusion-set", "course-of-action"):
                    from_ext = self._lookup_external_id(obj)
                    edge = {
                        "release_id": release_id,
                        "kind": "deprecated_no_successor",
                        "from": {
                            "stix_id": obj["id"],
                            "external_id": from_ext,
                        },
                        "to": None,
                        "evidence": {
                            "source": "mitre_bundle",
                            "basis": "deprecated_flag_no_successor",
                        },
                        "confidence": 1.0,
                    }
                    if self._upsert_edge(edge):
                        edges_inserted += 1

        logger.info(f"Built {edges_inserted} lineage edges for {release_id}")
        return edges_inserted

    def _make_edge(
        self,
        release_id: str,
        kind: str,
        from_stix_id: str,
        to_stix_id: str,
        evidence: dict,
    ) -> dict:
        from_ext = self._lookup_external_id_by_stix(from_stix_id)
        to_ext = self._lookup_external_id_by_stix(to_stix_id)

        return {
            "release_id": release_id,
            "kind": kind,
            "from": {"stix_id": from_stix_id, "external_id": from_ext},
            "to": {"stix_id": to_stix_id, "external_id": to_ext},
            "evidence": evidence,
            "confidence": 1.0,
        }

    def _upsert_edge(self, edge: dict) -> bool:
        try:
            self.db.identity_edges.insert_one(edge)
            return True
        except DuplicateKeyError:
            return False

    def _lookup_external_id(self, stix_obj: dict) -> str | None:
        for ref in stix_obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    def _lookup_external_id_by_stix(self, stix_id: str) -> str | None:
        member = self.db.release_members.find_one(
            {"stix_id": stix_id},
            {"external_id": 1},
        )
        if member:
            return member.get("external_id")
        return None
