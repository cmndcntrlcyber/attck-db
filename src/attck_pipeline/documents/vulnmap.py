from __future__ import annotations

from datetime import datetime

from beanie import Document


class CapecObjectDoc(Document):
    id: str
    capec_id: str
    name: str
    description: str | None = None
    severity: str | None = None
    likelihood: str | None = None
    attack_technique_ids: list[str] = []
    cwe_ids: list[str] = []
    raw: dict = {}

    class Settings:
        name = "capec_objects"


class VulnTechniqueEdgeDoc(Document):
    id: dict
    source_type: str
    source_id: str
    technique_ids: list[str] = []
    stix_ids: list[str] | None = None
    derivation: list[dict] = []
    confidence: float = 0.0
    release_id: str = ""
    computed_at: datetime | None = None
    source_meta: dict | None = None

    class Settings:
        name = "vuln_technique_edges"


class ScanSnapshotDoc(Document):
    id: str
    sha256: str
    source: str
    scan_type: str
    target: str
    assets: list[dict] = []
    captured_at: datetime
    recorded_from: datetime | None = None
    recorded_to: datetime | None = None

    class Settings:
        name = "scan_snapshots"


class AssetTechniqueMappingDoc(Document):
    id: dict
    scan_snapshot_id: str
    host: str
    hostname: str | None = None
    techniques: list[dict] = []
    release_id: str = ""
    computed_at: datetime | None = None
    recorded_from: datetime | None = None
    recorded_to: datetime | None = None

    class Settings:
        name = "asset_technique_mappings"
