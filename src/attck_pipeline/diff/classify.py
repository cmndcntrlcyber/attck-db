from __future__ import annotations

from dataclasses import dataclass, field


SEVERITY_MAP = {
    "kill_chain_phases": "high",
    "x_mitre_platforms": "high",
    "name": "medium",
    "description": "low",
    "external_references": "medium",
}

SEMANTIC_FIELDS = ["kill_chain_phases", "x_mitre_platforms", "name", "description", "external_references"]

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


@dataclass
class ModificationDetail:
    stix_id: str
    external_id: str | None
    changed_paths: list[str] = field(default_factory=list)
    max_severity: str = "low"


def classify_modification(old_raw: dict, new_raw: dict, stix_id: str, external_id: str | None) -> ModificationDetail:
    changed = diff_semantic_paths(old_raw, new_raw)
    max_sev = "low"
    for path in changed:
        sev = SEVERITY_MAP.get(path, "low")
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(max_sev, 0):
            max_sev = sev

    return ModificationDetail(
        stix_id=stix_id,
        external_id=external_id,
        changed_paths=changed,
        max_severity=max_sev,
    )


def diff_semantic_paths(old_raw: dict, new_raw: dict) -> list[str]:
    changed = []
    for field_name in SEMANTIC_FIELDS:
        old_val = old_raw.get(field_name)
        new_val = new_raw.get(field_name)
        if old_val != new_val:
            changed.append(field_name)
    return changed
