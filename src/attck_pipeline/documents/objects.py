from __future__ import annotations

from beanie import Document


class AttackObjectDoc(Document):
    id: str
    stix_id: str
    stix_type: str
    kind: str
    external_id: str | None = None
    name: str
    modified: str
    x_mitre_version: str | None = None
    revoked: bool = False
    deprecated: bool = False
    parent_stix_id: str | None = None
    tactic_shortnames: list[str] | None = None
    platforms: list[str] | None = None
    description: str | None = None
    x_mitre_shortname: str | None = None
    raw: dict

    class Settings:
        name = "attack_objects"
