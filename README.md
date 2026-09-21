# Liszt — ATT&CK Knowledge Pipeline

Release-pinned technique identity, drift detection, and reproducible reporting on MongoDB.

Liszt ingests [MITRE ATT&CK](https://attack.mitre.org/) STIX 2.x bundles, tracks technique identity across framework releases, detects when revocations or deprecations impact your engagement scenarios, and produces hash-verified reports. It bridges offensive tooling data from [SpecterOps Nemesis](https://github.com/SpecterOps/Nemesis) and curated overlays from Notion into a unified, version-aware knowledge base.

## What it solves

When MITRE revokes a technique (e.g., T1086 PowerShell becomes T1059.001), every scenario referencing that technique needs to be identified, flagged, and optionally remapped — without breaking existing reports that pin the old revision. Liszt automates this across three ATT&CK domains (Enterprise, Mobile, ICS), 7-year audit retention, and multiple external data sources.

## Quick start

### 1. Infrastructure

```bash
# MongoDB replica set (required for transactions)
docker run -d --name liszt-mongo -p 27017:27017 mongo:7.0.7 --replSet rs0
docker exec liszt-mongo mongosh --eval "rs.initiate()"

# MinIO (S3-compatible storage)
docker run -d --name liszt-minio -p 9000:9000 -p 9001:9001 \
  minio/minio server /data --console-address ":9001"
```

### 2. Install

```bash
git clone https://github.com/cmndcntrlcyber/attck-db.git
cd attck-db
cp .env.example .env   # edit with your values
pip install -e ".[dev]"
```

### 3. Initialize and ingest

```bash
liszt init-db          # create collections with $jsonSchema validators + indexes
liszt init-storage     # create S3 buckets

liszt ingest enterprise-attack 16.0
liszt ingest enterprise-attack 16.1
liszt diff enterprise-attack@16.0 enterprise-attack@16.1
liszt search "PowerShell"
```

### 4. Start the API

```bash
liszt serve            # http://localhost:8000/docs
```

## Architecture

### Two-database split

| Database | Purpose | Collections |
|----------|---------|-------------|
| `liszt` | Public framework data | `framework_releases`, `attack_objects`, `release_members`, `identity_edges`, `release_diffs`, `overlay_snapshots`, `ingest_quarantine`, `ingest_runs` |
| `liszt_secure` | Classification-sensitive data | `scenarios`, `scenario_attack_refs`, `drift_findings`, `reports` |

### Content addressing

Every STIX object is canonicalized via [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JSON Canonicalization Scheme) and stored by its SHA-256 hash. Unchanged objects share a hash across releases, so storage grows only with real edits. Report manifests pin every input by hash for byte-level reproducibility.

### Data flow

```
MITRE STIX bundles ──→ ingest ──→ lineage ──→ diff ──→ impact ──→ notify/remap
                         │                      │          │
                         ▼                      ▼          ▼
                    attack_objects         release_diffs  drift_findings
                    release_members        (sealed)       (work queue)
                    identity_edges

Notion overlay ──→ overlay_snapshots ──→ reports (manifest + rendered artifact)
Nemesis findings ──→ overlay_snapshots ──→
```

### External integrations

| Source | Protocol | Purpose |
|--------|----------|---------|
| MITRE ATT&CK | STIX bundles via GitHub | Framework truth |
| Notion | REST API | Curated overlay (POC refs, emulation plans, actor tags) |
| SpecterOps Nemesis | Hasura GraphQL | Offensive findings mapped to ATT&CK techniques |
| MinIO/S3 | S3 API | Immutable bundle and report artifact storage |
| GitHub | Release polling | Automated ingest trigger for new ATT&CK versions |

## CLI reference

```
liszt init-db                                 # Create collections, schemas, indexes
liszt init-storage                            # Create S3 buckets
liszt ingest <domain> <version>               # Ingest a STIX bundle
liszt diff <from_release> <to_release>        # Compute release-to-release diff
liszt impact <diff_id>                        # Detect drift impact on scenarios
liszt remap --diff-id <id> --auto             # Auto-remap eligible findings
liszt remap --finding-id <id>                 # Accept a single finding
liszt overlay-sync                            # Snapshot Notion overlay
liszt nemesis-sync                            # Sync Nemesis findings
liszt report-build <report_id>                # Render report (JSON/HTML/PDF)
liszt report-rebuild <report_id> --verify     # Rebuild and verify hash
liszt watch --interval 3600                   # Poll GitHub for new releases
liszt lineage <stix_id> <release_id>          # Resolve revocation chain
liszt search <query> --kind technique         # Search techniques by name
liszt serve --port 8000                       # Start FastAPI server
```

## REST API

Start with `liszt serve`. Swagger UI at `http://localhost:8000/docs`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/releases` | List framework releases (filter by domain, status) |
| GET | `/releases/{id}` | Release detail |
| POST | `/ingest` | Trigger ingest (`{"domain": "...", "version": "..."}`) |
| GET | `/diffs/{id}` | Diff detail |
| GET | `/findings` | List drift findings (filter by status, diff_id) |
| POST | `/findings/{id}/accept` | Accept finding and trigger remap |
| GET | `/scenarios/{id}` | Scenario head (add `?include_history=true` for all revisions) |
| GET | `/reports/{id}` | Report manifest |
| POST | `/reports/{id}/rebuild` | Trigger rebuild with verification |
| GET | `/overlay/latest` | Latest Notion overlay snapshot |
| POST | `/overlay/sync` | Trigger Notion sync |
| GET | `/nemesis/latest` | Latest Nemesis snapshot |
| GET | `/nemesis/mappings` | Finding-to-technique mapping table |
| POST | `/nemesis/sync` | Trigger Nemesis sync |

Mutating endpoints return HTTP 202 and execute in background tasks.

## Dagster orchestration (optional)

```bash
pip install attck-pipeline[dagster]
dagster dev -m attck_pipeline.orchestration.definitions
# Dagster UI at http://localhost:3000
```

12 software-defined assets across 3 graphs:

- **Ingest**: `stix_bundle` → `stored_bundle` → `loaded_objects` → `lineage_edges`
- **Diff/Impact**: `release_diff` → `sealed_release` → `drift_findings` → `finding_notifications` + `auto_remap_results`
- **Overlay**: `overlay_snapshot`, `nemesis_snapshot`
- **Reports**: `rendered_report`

The `github_release_sensor` polls hourly and triggers ingest runs for new ATT&CK versions.

## Nemesis integration

Nemesis findings are mapped to ATT&CK techniques via a curated lookup table in `sources/nemesis_mapping.py`. The mapping resolves by exact match → prefix match → category fallback. Unmapped findings route to `ingest_quarantine`.

| Nemesis Category | Example Finding | ATT&CK Technique |
|------------------|----------------|-------------------|
| CREDENTIAL | chromium_logins | T1555.003 |
| CREDENTIAL | dpapi_masterkey | T1555.004 |
| CREDENTIAL | gpp_passwords | T1552.006 |
| EXTRACTED_HASH | ntlm_hash | T1003.001 |
| EXTRACTED_DATA | keytab | T1558 |
| EXTRACTED_DATA | lsass_dump | T1003.001 |

Configure with `LISZT_NEMESIS_URL` and `LISZT_NEMESIS_HASURA_SECRET`.

## Configuration

All variables use the `LISZT_` prefix. Copy `.env.example` to `.env`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `LISZT_MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection |
| `LISZT_DB_NAME` / `_SECURE_NAME` | `liszt` / `liszt_secure` | Database names |
| `LISZT_S3_ENDPOINT_URL` | `http://localhost:9000` | MinIO/S3 endpoint |
| `LISZT_S3_ACCESS_KEY` / `_SECRET_KEY` | `minioadmin` | S3 credentials |
| `LISZT_S3_BUCKET_BUNDLES` / `_REPORTS` | `attck-bundles` / `liszt-reports` | Bucket names |
| `LISZT_S3_ENABLE_OBJECT_LOCK` | `false` | WORM compliance mode |
| `LISZT_GITHUB_TOKEN` | (empty) | GitHub PAT for higher rate limits |
| `LISZT_NOTION_TOKEN` | (empty) | Notion integration token |
| `LISZT_NEMESIS_URL` | (empty) | Nemesis instance URL |
| `LISZT_NEMESIS_HASURA_SECRET` | (empty) | Hasura admin secret |
| `LISZT_NEMESIS_MIN_SEVERITY` | `0` | Minimum finding severity to sync |
| `LISZT_RETENTION_YEARS` | `7` | S3 Object Lock retention |
| `LISZT_WATCH_DOMAINS` | `["enterprise-attack","mobile-attack","ics-attack"]` | Domains to poll |
| `LISZT_API_HOST` / `_PORT` | `0.0.0.0` / `8000` | API server bind |

## Data quality checks

11 checks run after each pipeline stage, callable standalone or via Dagster:

| Stage | Check | Severity |
|-------|-------|----------|
| Post-ingest | Object count matches bundle | error |
| Post-ingest | No duplicate STIX IDs in release | error |
| Post-ingest | Techniques have tactic_shortnames | warning |
| Post-lineage | Revoked objects have edges | error |
| Post-lineage | No orphan edges | warning |
| Post-diff | Summary counts match detail arrays | error |
| Post-diff | Revoked have successors listed | warning |
| Post-impact | Findings count matches affected scenarios | error |
| Post-impact | All findings have status "open" | error |
| Post-overlay | No quarantine items in main data | error |
| Post-overlay | Snapshot hash verifiable | error |

## Testing

```bash
pip install -e ".[dev]"
pytest                           # 93 tests (78 pass with mongomock, 15 need real MongoDB)
sg docker -c "pytest"            # All 93 with testcontainers MongoDB
pytest tests/test_tag_normalizer.py  # Run a single test file
```

Tests use mongomock as a fallback when Docker is unavailable. Schema validation tests (`$jsonSchema` enforcement) require a real MongoDB instance via testcontainers.

## Project structure

```
src/attck_pipeline/
  canonical.py             RFC 8785 canonicalization + SHA-256
  cli.py                   Typer CLI (14 commands)
  config.py                Pydantic Settings (LISZT_ prefix)
  storage.py               S3/MinIO storage layer

  api/                     FastAPI REST API (8 routers)
  checks/                  Data quality checks (11 checks, 5 modules)
  db/                      MongoDB setup, schemas, indexes, transactions, Motor/Beanie init
  diff/                    Release-to-release diff engine + classification
  documents/               Beanie ODM document classes (12 collections)
  impact/                  Drift detection + notification
  ingest/                  STIX loader + lineage builder
  models/                  Pydantic domain models
  orchestration/           Dagster assets, resources, sensors (optional)
  query/                   Lineage resolver ($graphLookup) + text search
  reports/                 Manifest builder, renderer (Jinja2 + WeasyPrint), rebuild verifier
  scenarios/               Revision manager + auto-remap engine
  sources/                 MITRE STIX, Notion, Nemesis, GitHub watch, tag normalizer

tests/
  fixtures/                Minimal STIX bundles (v6.3, v7.0), 40 scenarios, Notion rows
  test_*.py                93 tests across 10 files
```

## License

Internal use.
