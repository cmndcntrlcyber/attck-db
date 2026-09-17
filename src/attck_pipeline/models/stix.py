from __future__ import annotations

from attck_pipeline.canonical import content_hash

STIX_TYPE_TO_KIND = {
    "x-mitre-tactic": "tactic",
    "intrusion-set": "group",
    "malware": "software",
    "tool": "software",
    "course-of-action": "mitigation",
    "x-mitre-data-source": "datasource",
    "x-mitre-data-component": "datacomponent",
    "campaign": "campaign",
    "x-mitre-matrix": "matrix",
    "x-mitre-collection": "collection",
}

SKIPPED_TYPES = {"identity", "marking-definition", "relationship"}


def classify_kind(stix_obj: dict, custom_prefix: str = "x-cmndcntrl-custom-") -> str | None:
    stix_type = stix_obj.get("type", "")

    if stix_type in SKIPPED_TYPES:
        return None

    if stix_type.startswith(custom_prefix):
        return "custom"

    if stix_type == "attack-pattern":
        if stix_obj.get("x_mitre_is_subtechnique", False):
            return "subtechnique"
        return "technique"

    return STIX_TYPE_TO_KIND.get(stix_type)


def extract_external_id(stix_obj: dict) -> str | None:
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def extract_tactic_shortnames(stix_obj: dict) -> list[str] | None:
    phases = stix_obj.get("kill_chain_phases", [])
    if not phases:
        return None
    return [p["phase_name"] for p in phases if p.get("kill_chain_name") == "mitre-attack"]


def determine_state(stix_obj: dict) -> str:
    if stix_obj.get("revoked", False):
        return "revoked"
    if stix_obj.get("x_mitre_deprecated", False):
        return "deprecated"
    return "active"


def stix_to_attack_object(stix_obj: dict, custom_prefix: str = "x-cmndcntrl-custom-") -> dict | None:
    kind = classify_kind(stix_obj, custom_prefix)
    if kind is None:
        return None

    obj_hash = content_hash(stix_obj)

    doc = {
        "_id": obj_hash,
        "stix_id": stix_obj["id"],
        "stix_type": stix_obj["type"],
        "kind": kind,
        "external_id": extract_external_id(stix_obj),
        "name": stix_obj.get("name", ""),
        "modified": stix_obj.get("modified", ""),
        "x_mitre_version": stix_obj.get("x_mitre_version"),
        "revoked": stix_obj.get("revoked", False),
        "deprecated": stix_obj.get("x_mitre_deprecated", False),
        "parent_stix_id": None,
        "tactic_shortnames": extract_tactic_shortnames(stix_obj),
        "platforms": stix_obj.get("x_mitre_platforms"),
        "description": stix_obj.get("description"),
        "raw": stix_obj,
    }

    if kind == "tactic":
        doc["x_mitre_shortname"] = stix_obj.get("x_mitre_shortname", "")

    return doc
