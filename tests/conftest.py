import json
from pathlib import Path
from uuid import uuid4

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"

_USE_REAL_MONGO = False
_mongo_container_instance = None
_mongo_client_instance = None


def _try_docker_mongo():
    global _USE_REAL_MONGO, _mongo_container_instance, _mongo_client_instance
    try:
        from testcontainers.community.mongodb import MongoDbContainer
        from pymongo import MongoClient

        container = MongoDbContainer("mongo:7.0.7")
        container.start()
        client = MongoClient(
            container.get_connection_url(),
            directConnection=True,
            serverSelectionTimeoutMS=5000,
        )
        client.admin.command("ping")
        _mongo_container_instance = container
        _mongo_client_instance = client
        _USE_REAL_MONGO = True
        return True
    except Exception as e:
        print(f"Docker MongoDB unavailable: {e}")
        return False


def _get_mongomock_client():
    import mongomock
    return mongomock.MongoClient()


def _is_mongo_alive():
    if not _mongo_client_instance:
        return False
    try:
        _mongo_client_instance.admin.command("ping")
        return True
    except Exception:
        return False


def pytest_configure(config):
    config.addinivalue_line("markers", "requires_real_mongo: test needs a real MongoDB instance")
    _try_docker_mongo()


def pytest_collection_modifyitems(config, items):
    if _USE_REAL_MONGO:
        return
    skip_marker = pytest.mark.skip(reason="Requires real MongoDB (Docker not accessible)")
    for item in items:
        if "requires_real_mongo" in item.keywords:
            item.add_marker(skip_marker)


def pytest_sessionfinish(session, exitstatus):
    global _mongo_client_instance, _mongo_container_instance
    if _mongo_client_instance:
        try:
            _mongo_client_instance.close()
        except Exception:
            pass
    if _mongo_container_instance:
        try:
            _mongo_container_instance.stop()
        except Exception:
            pass


def _init_db_real(client, db_name):
    from attck_pipeline.db.setup import initialize_database
    db = client[db_name]
    initialize_database(db)
    return db


def _init_db_mock(client, db_name):
    from attck_pipeline.db.indexes import (
        attack_objects_indexes, framework_releases_indexes,
        identity_edges_indexes, ingest_quarantine_indexes,
        ingest_runs_indexes, overlay_snapshots_indexes,
        release_diffs_indexes, release_members_indexes,
    )
    db = client[db_name]
    collections_indexes = {
        "framework_releases": framework_releases_indexes,
        "attack_objects": attack_objects_indexes,
        "release_members": release_members_indexes,
        "identity_edges": identity_edges_indexes,
        "release_diffs": release_diffs_indexes,
        "overlay_snapshots": overlay_snapshots_indexes,
        "ingest_quarantine": ingest_quarantine_indexes,
        "ingest_runs": ingest_runs_indexes,
    }
    for name, idx_fn in collections_indexes.items():
        if name not in db.list_collection_names():
            db.create_collection(name)
        idx_models = idx_fn()
        if idx_models:
            try:
                db[name].create_indexes(idx_models)
            except Exception:
                pass
    return db


def _init_secure_db_real(client, db_name):
    from attck_pipeline.db.setup import initialize_secure_database
    db = client[db_name]
    initialize_secure_database(db)
    return db


def _init_secure_db_mock(client, db_name):
    from pymongo import ASCENDING, IndexModel
    db = client[db_name]
    for name in ("scenarios", "scenario_attack_refs", "drift_findings", "reports"):
        if name not in db.list_collection_names():
            db.create_collection(name)

    db.scenarios.create_indexes([
        IndexModel([("scenario_id", ASCENDING), ("rev", ASCENDING)]),
    ])
    db.scenario_attack_refs.create_indexes([
        IndexModel([("stix_id", ASCENDING), ("is_head", ASCENDING)]),
        IndexModel([("scenario_id", ASCENDING), ("rev", ASCENDING)]),
    ])
    db.drift_findings.create_indexes([
        IndexModel(
            [("diff_id", ASCENDING), ("scenario_id", ASCENDING),
             ("scenario_rev", ASCENDING), ("step_id", ASCENDING)],
            unique=True,
        ),
    ])
    return db


@pytest.fixture()
def mongo_client():
    if _USE_REAL_MONGO and _is_mongo_alive():
        return _mongo_client_instance
    return _get_mongomock_client()


@pytest.fixture()
def db(mongo_client):
    db_name = f"test_{uuid4().hex[:8]}"
    use_real = _USE_REAL_MONGO and _is_mongo_alive() and mongo_client is _mongo_client_instance
    if use_real:
        db = _init_db_real(mongo_client, db_name)
    else:
        db = _init_db_mock(mongo_client, db_name)
    yield db
    try:
        mongo_client.drop_database(db_name)
    except Exception:
        pass


@pytest.fixture()
def secure_db(mongo_client):
    db_name = f"test_secure_{uuid4().hex[:8]}"
    use_real = _USE_REAL_MONGO and _is_mongo_alive() and mongo_client is _mongo_client_instance
    if use_real:
        db = _init_secure_db_real(mongo_client, db_name)
    else:
        db = _init_secure_db_mock(mongo_client, db_name)
    yield db
    try:
        mongo_client.drop_database(db_name)
    except Exception:
        pass


@pytest.fixture()
def both_dbs(mongo_client):
    pub_name = f"test_{uuid4().hex[:8]}"
    sec_name = f"test_secure_{uuid4().hex[:8]}"
    use_real = _USE_REAL_MONGO and _is_mongo_alive() and mongo_client is _mongo_client_instance
    if use_real:
        pub_db = _init_db_real(mongo_client, pub_name)
        sec_db = _init_secure_db_real(mongo_client, sec_name)
    else:
        pub_db = _init_db_mock(mongo_client, pub_name)
        sec_db = _init_secure_db_mock(mongo_client, sec_name)
    yield pub_db, sec_db
    try:
        mongo_client.drop_database(pub_name)
        mongo_client.drop_database(sec_name)
    except Exception:
        pass


def load_fixture(name: str) -> dict | list:
    return json.loads((FIXTURES_DIR / name).read_text())
