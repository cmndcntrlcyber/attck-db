from __future__ import annotations

import json

import httpx
from loguru import logger

from attck_pipeline.canonical import bundle_hash, content_hash
from attck_pipeline.config import Settings


def _extract_capec_id(stix_obj: dict) -> str | None:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "capec":
            return ref.get("external_id")
    return None


def _extract_attack_technique_ids(stix_obj: dict) -> list[str]:
    technique_ids = []
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            ext_id = ref.get("external_id", "")
            if ext_id.startswith("T"):
                technique_ids.append(ext_id)
    return technique_ids


def _extract_cwe_ids(stix_obj: dict) -> list[str]:
    cwe_ids = []
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "cwe":
            ext_id = ref.get("external_id", "")
            if ext_id.startswith("CWE-"):
                cwe_ids.append(ext_id)
    return cwe_ids


def _extract_severity(stix_obj: dict) -> str | None:
    return stix_obj.get("x_capec_typical_severity")


def _extract_likelihood(stix_obj: dict) -> str | None:
    return stix_obj.get("x_capec_likelihood_of_attack")


class CapecSource:
    def __init__(self, settings: Settings | None = None, client: httpx.Client | None = None):
        self.settings = settings or Settings()
        self.client = client or httpx.Client(timeout=120.0)
        self.base_url = (
            f"https://raw.githubusercontent.com/"
            f"{self.settings.capec_stix_repo}/{self.settings.capec_stix_branch}"
        )

    def fetch_bundle(self) -> tuple[bytes, str]:
        url = f"{self.base_url}/{self.settings.capec_stix_path}"
        logger.info(f"Fetching CAPEC STIX bundle from {url}")
        resp = self.client.get(url)
        resp.raise_for_status()
        raw = resp.content
        sha = bundle_hash(raw)
        return raw, sha

    def parse_bundle(self, raw_bytes: bytes) -> list[dict]:
        bundle = json.loads(raw_bytes)
        objects = bundle.get("objects", [])
        capec_docs = []

        relationships = [o for o in objects if o.get("type") == "relationship"]
        attack_pattern_ids: dict[str, list[str]] = {}
        cwe_map: dict[str, list[str]] = {}

        for rel in relationships:
            if rel.get("relationship_type") != "uses":
                continue
            source_ref = rel.get("source_ref", "")
            target_ref = rel.get("target_ref", "")
            if not source_ref.startswith("attack-pattern--"):
                continue
            if target_ref.startswith("attack-pattern--"):
                target_obj = next(
                    (o for o in objects if o.get("id") == target_ref and o.get("type") == "attack-pattern"),
                    None,
                )
                if target_obj:
                    for ref in target_obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            ext_id = ref.get("external_id", "")
                            if ext_id.startswith("T"):
                                attack_pattern_ids.setdefault(source_ref, []).append(ext_id)

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue

            capec_id = _extract_capec_id(obj)
            if not capec_id:
                continue

            technique_ids = _extract_attack_technique_ids(obj)
            rel_technique_ids = attack_pattern_ids.get(obj["id"], [])
            all_technique_ids = sorted(set(technique_ids + rel_technique_ids))

            cwe_ids = _extract_cwe_ids(obj)

            obj_hash = content_hash({
                "capec_id": capec_id,
                "name": obj.get("name", ""),
                "attack_technique_ids": all_technique_ids,
                "cwe_ids": cwe_ids,
            })

            capec_docs.append({
                "_id": obj_hash,
                "capec_id": capec_id,
                "name": obj.get("name", ""),
                "description": obj.get("description"),
                "severity": _extract_severity(obj),
                "likelihood": _extract_likelihood(obj),
                "attack_technique_ids": all_technique_ids,
                "cwe_ids": cwe_ids,
                "raw": obj,
            })

        logger.info(f"Parsed {len(capec_docs)} CAPEC attack patterns")
        return capec_docs

    def ingest(self, db=None) -> dict:
        raw_bytes, sha = self.fetch_bundle()
        capec_docs = self.parse_bundle(raw_bytes)

        stats = {"fetched": len(capec_docs), "inserted": 0, "updated": 0}

        if db:
            for doc in capec_docs:
                result = db.capec_objects.update_one(
                    {"capec_id": doc["capec_id"]},
                    {"$set": doc},
                    upsert=True,
                )
                if result.upserted_id:
                    stats["inserted"] += 1
                elif result.modified_count:
                    stats["updated"] += 1

        logger.info(
            f"CAPEC ingest complete: {stats['fetched']} patterns, "
            f"{stats['inserted']} inserted, {stats['updated']} updated"
        )
        return stats
