from pymongo import ASCENDING, TEXT, IndexModel


def framework_releases_indexes() -> list[IndexModel]:
    return [
        IndexModel([("domain", ASCENDING), ("version", ASCENDING)], unique=True),
    ]


def attack_objects_indexes() -> list[IndexModel]:
    return [
        IndexModel([("stix_id", ASCENDING)]),
        IndexModel([("kind", ASCENDING)]),
        IndexModel([("external_id", ASCENDING)]),
        IndexModel(
            [("name", TEXT), ("description", TEXT)],
            weights={"name": 10, "description": 1},
            name="attack_objects_text",
            default_language="english",
        ),
    ]


def release_members_indexes() -> list[IndexModel]:
    return [
        IndexModel([("release_id", ASCENDING), ("external_id", ASCENDING)]),
        IndexModel([("stix_id", ASCENDING), ("release_id", ASCENDING)]),
    ]


def identity_edges_indexes() -> list[IndexModel]:
    return [
        IndexModel(
            [
                ("release_id", ASCENDING),
                ("kind", ASCENDING),
                ("from.stix_id", ASCENDING),
                ("to.stix_id", ASCENDING),
            ],
            unique=True,
        ),
    ]


def release_diffs_indexes() -> list[IndexModel]:
    return []


def scenarios_indexes() -> list[IndexModel]:
    return [
        IndexModel(
            [("scenario_id", ASCENDING)],
            unique=True,
            partialFilterExpression={"is_head": True},
        ),
        IndexModel([("scenario_id", ASCENDING), ("rev", ASCENDING)]),
    ]


def scenario_attack_refs_indexes() -> list[IndexModel]:
    return [
        IndexModel([("stix_id", ASCENDING), ("is_head", ASCENDING)]),
        IndexModel([("scenario_id", ASCENDING), ("rev", ASCENDING)]),
    ]


def drift_findings_indexes() -> list[IndexModel]:
    return [
        IndexModel(
            [
                ("diff_id", ASCENDING),
                ("scenario_id", ASCENDING),
                ("scenario_rev", ASCENDING),
                ("step_id", ASCENDING),
            ],
            unique=True,
        ),
        IndexModel([("status", ASCENDING)]),
    ]


def reports_indexes() -> list[IndexModel]:
    return [
        IndexModel([("manifest.scenario_set.scenario_id", ASCENDING)]),
    ]


def overlay_snapshots_indexes() -> list[IndexModel]:
    return []


def ingest_quarantine_indexes() -> list[IndexModel]:
    return [
        IndexModel([("source", ASCENDING), ("value", ASCENDING)]),
    ]


def ingest_runs_indexes() -> list[IndexModel]:
    return [
        IndexModel([("release_id", ASCENDING)]),
    ]
