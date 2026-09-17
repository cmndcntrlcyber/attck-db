from pymongo.database import Database

from attck_pipeline.db import indexes, schemas

PUBLIC_COLLECTIONS = {
    "framework_releases": (schemas.framework_releases_schema, indexes.framework_releases_indexes),
    "attack_objects": (schemas.attack_objects_schema, indexes.attack_objects_indexes),
    "release_members": (schemas.release_members_schema, indexes.release_members_indexes),
    "identity_edges": (schemas.identity_edges_schema, indexes.identity_edges_indexes),
    "release_diffs": (schemas.release_diffs_schema, indexes.release_diffs_indexes),
    "overlay_snapshots": (schemas.overlay_snapshots_schema, indexes.overlay_snapshots_indexes),
    "ingest_quarantine": (schemas.ingest_quarantine_schema, indexes.ingest_quarantine_indexes),
    "ingest_runs": (schemas.ingest_runs_schema, indexes.ingest_runs_indexes),
}

SECURE_COLLECTIONS = {
    "scenarios": (schemas.scenarios_schema, indexes.scenarios_indexes),
    "scenario_attack_refs": (schemas.scenario_attack_refs_schema, indexes.scenario_attack_refs_indexes),
    "drift_findings": (schemas.drift_findings_schema, indexes.drift_findings_indexes),
    "reports": (schemas.reports_schema, indexes.reports_indexes),
}


def _ensure_collections(db: Database, collection_defs: dict) -> None:
    existing = set(db.list_collection_names())
    for name, (schema_fn, index_fn) in collection_defs.items():
        schema = schema_fn()
        if name not in existing:
            db.create_collection(
                name,
                validator={"$jsonSchema": schema},
                validationAction="error",
            )
        else:
            db.command("collMod", name, validator={"$jsonSchema": schema}, validationAction="error")
        idx_models = index_fn()
        if idx_models:
            db[name].create_indexes(idx_models)


def initialize_database(db: Database) -> None:
    _ensure_collections(db, PUBLIC_COLLECTIONS)


def initialize_secure_database(db: Database) -> None:
    _ensure_collections(db, SECURE_COLLECTIONS)
