from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from loguru import logger
from pymongo.database import Database

SERVICE_TECHNIQUE_MAP: dict[str, list[str]] = {
    "mssql": ["T1078.001", "T1552.001", "T1505.001", "T1059"],
    "ms-sql-s": ["T1078.001", "T1552.001", "T1505.001", "T1059"],
    "smb": ["T1021.002", "T1039", "T1135"],
    "microsoft-ds": ["T1021.002", "T1039", "T1135"],
    "ldap": ["T1087.002", "T1069.002", "T1482"],
    "kerberos": ["T1558.003", "T1558.004"],
    "kerberos-sec": ["T1558.003", "T1558.004"],
    "rdp": ["T1021.001", "T1563.002"],
    "ms-wbt-server": ["T1021.001", "T1563.002"],
    "ssh": ["T1021.004", "T1098.004"],
    "http": ["T1190", "T1059.007"],
    "https": ["T1190", "T1059.007"],
    "http-proxy": ["T1190"],
    "ftp": ["T1078.001", "T1552.001"],
    "smtp": ["T1566", "T1071.003"],
    "dns": ["T1071.004", "T1568"],
    "domain": ["T1071.004", "T1568"],
    "winrm": ["T1021.006"],
    "wsman": ["T1021.006"],
    "postgresql": ["T1190", "T1505.001"],
    "mysql": ["T1190", "T1505.001"],
    "adcs": ["T1649", "T1552.004", "T1558"],
    "airflow": ["T1190", "T1059.006"],
    "metabase": ["T1190", "T1059.007"],
    "minio": ["T1530", "T1078.001"],
    "vnc": ["T1021.005"],
    "telnet": ["T1021", "T1078.001"],
    "snmp": ["T1602"],
    "nfs": ["T1039", "T1005"],
    "docker": ["T1610", "T1611"],
}


@dataclass
class VulnMappingResult:
    source_type: str
    source_id: str
    techniques: list[str] = field(default_factory=list)
    derivation: list[dict] = field(default_factory=list)
    confidence: float = 0.0
    match_type: str = "none"


def _resolve_latest_release(db: Database) -> str | None:
    release = db.framework_releases.find_one(
        {"domain": "enterprise-attack", "status": "sealed"},
        sort=[("ingested_at", -1)],
    )
    return release["_id"] if release else None


def _resolve_technique_via_lineage(
    technique_id: str, db: Database, release_id: str
) -> tuple[str, list[dict]]:
    member = db.release_members.find_one({
        "release_id": release_id,
        "external_id": technique_id,
    })
    if not member:
        return technique_id, []

    if member["state"] == "active":
        return technique_id, []

    from attck_pipeline.query.lineage import LineageResolver

    resolver = LineageResolver(db)
    result = resolver.resolve_to_active(member["stix_id"], release_id)

    if not result["terminal"]:
        return technique_id, []

    terminal_member = db.release_members.find_one({
        "release_id": release_id,
        "stix_id": result["terminal"],
    })
    if not terminal_member or not terminal_member.get("external_id"):
        return technique_id, []

    new_id = terminal_member["external_id"]
    lineage_steps = [
        {"step": "lineage_resolve", "from": technique_id, "to": new_id, "depth": len(result["chain"])}
    ]
    return new_id, lineage_steps


def _resolve_with_lineage(
    technique_ids: list[str], db: Database, release_id: str
) -> tuple[list[str], list[dict]]:
    resolved = []
    lineage_derivations = []
    for tid in technique_ids:
        new_tid, steps = _resolve_technique_via_lineage(tid, db, release_id)
        resolved.append(new_tid)
        lineage_derivations.extend(steps)
    return sorted(set(resolved)), lineage_derivations


def resolve_cwe_to_techniques(cwe_id: str, db: Database, release_id: str | None = None) -> VulnMappingResult:
    if not release_id:
        release_id = _resolve_latest_release(db) or ""

    capec_docs = list(db.capec_objects.find({"cwe_ids": cwe_id}))
    if not capec_docs:
        return VulnMappingResult(
            source_type="cwe", source_id=cwe_id, match_type="none",
        )

    all_technique_ids = []
    derivation = []
    for capec_doc in capec_docs:
        capec_id = capec_doc["capec_id"]
        for tid in capec_doc["attack_technique_ids"]:
            derivation.append({"step": "cwe_capec", "from": cwe_id, "to": capec_id})
            derivation.append({"step": "capec_attack", "from": capec_id, "to": tid})
            all_technique_ids.append(tid)

    resolved, lineage_steps = _resolve_with_lineage(all_technique_ids, db, release_id)
    derivation.extend(lineage_steps)

    return VulnMappingResult(
        source_type="cwe",
        source_id=cwe_id,
        techniques=resolved,
        derivation=derivation,
        confidence=0.7,
        match_type="chain",
    )


def resolve_cve_to_techniques(
    cve_id: str, db: Database, release_id: str | None = None, nvd_client=None,
) -> VulnMappingResult:
    if not release_id:
        release_id = _resolve_latest_release(db) or ""

    cached = db.vuln_technique_edges.find_one({
        "_id": {"source_type": "cve", "source_id": cve_id},
    })
    if cached:
        return VulnMappingResult(
            source_type="cve",
            source_id=cve_id,
            techniques=cached["technique_ids"],
            derivation=cached["derivation"],
            confidence=cached["confidence"],
            match_type="exact",
        )

    if nvd_client is None:
        from attck_pipeline.sources.nvd_client import NvdClient
        nvd_client = NvdClient()

    cwe_ids = nvd_client.get_cwe_ids(cve_id)
    if not cwe_ids:
        result = VulnMappingResult(
            source_type="cve", source_id=cve_id, match_type="none",
        )
        _cache_edge(db, result, release_id)
        return result

    all_techniques = []
    all_derivation = [{"step": "nvd_cwe", "from": cve_id, "to": cwe_id} for cwe_id in cwe_ids]

    for cwe_id in cwe_ids:
        cwe_result = resolve_cwe_to_techniques(cwe_id, db, release_id)
        all_techniques.extend(cwe_result.techniques)
        all_derivation.extend(cwe_result.derivation)

    techniques = sorted(set(all_techniques))
    confidence = 0.85 if techniques else 0.0

    result = VulnMappingResult(
        source_type="cve",
        source_id=cve_id,
        techniques=techniques,
        derivation=all_derivation,
        confidence=confidence,
        match_type="chain" if techniques else "none",
    )
    _cache_edge(db, result, release_id)
    return result


def resolve_service_to_techniques(
    service_name: str, db: Database, release_id: str | None = None,
) -> VulnMappingResult:
    if not release_id:
        release_id = _resolve_latest_release(db) or ""

    key = service_name.lower().strip()
    technique_ids = SERVICE_TECHNIQUE_MAP.get(key, [])

    if not technique_ids:
        return VulnMappingResult(
            source_type="service", source_id=service_name, match_type="none",
        )

    resolved, lineage_steps = _resolve_with_lineage(technique_ids, db, release_id)
    derivation = [{"step": "service_map", "from": service_name, "to": tid} for tid in technique_ids]
    derivation.extend(lineage_steps)

    return VulnMappingResult(
        source_type="service",
        source_id=service_name,
        techniques=resolved,
        derivation=derivation,
        confidence=0.6,
        match_type="heuristic",
    )


def _cache_edge(db: Database, result: VulnMappingResult, release_id: str) -> None:
    now = datetime.now(timezone.utc)
    doc = {
        "_id": {"source_type": result.source_type, "source_id": result.source_id},
        "source_type": result.source_type,
        "source_id": result.source_id,
        "technique_ids": result.techniques,
        "stix_ids": None,
        "derivation": result.derivation,
        "confidence": result.confidence,
        "release_id": release_id,
        "computed_at": now,
        "source_meta": None,
    }
    db.vuln_technique_edges.update_one(
        {"_id": doc["_id"]},
        {"$set": doc},
        upsert=True,
    )


def get_service_mappings() -> list[dict]:
    results = []
    for service, techniques in SERVICE_TECHNIQUE_MAP.items():
        results.append({
            "service": service,
            "techniques": techniques,
        })
    return sorted(results, key=lambda r: r["service"])
