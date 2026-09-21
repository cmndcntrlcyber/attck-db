from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
from loguru import logger

from attck_pipeline.canonical import content_hash
from attck_pipeline.config import Settings
from attck_pipeline.sources.nemesis_mapping import MappingResult, resolve_techniques

FINDINGS_QUERY = """
query FetchFindings($limit: Int!, $offset: Int!, $since: timestamptz, $min_severity: Int) {
  findings(
    limit: $limit
    offset: $offset
    where: {
      _and: [
        { created_at: { _gte: $since } }
        { severity: { _gte: $min_severity } }
      ]
    }
    order_by: { created_at: asc }
  ) {
    id
    finding_name
    category
    severity
    origin_type
    origin_name
    data
    triage_value
    created_at
    updated_at
    files_enriched {
      file_name
      extension
      hashes
      object_id
    }
  }
}
"""


class NemesisSource:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.settings.nemesis_url,
                headers={
                    "Content-Type": "application/json",
                    "x-hasura-admin-secret": self.settings.nemesis_hasura_secret,
                },
                timeout=60.0,
            )
        return self._client

    def fetch_all_findings(self, since: datetime | None = None) -> list[dict]:
        findings = []
        offset = 0
        limit = 100

        variables: dict = {
            "limit": limit,
            "offset": offset,
            "since": since.isoformat() if since else "1970-01-01T00:00:00Z",
            "min_severity": self.settings.nemesis_min_severity,
        }

        while True:
            variables["offset"] = offset
            resp = self.client.post(
                "/hasura/v1/graphql",
                json={"query": FINDINGS_QUERY, "variables": variables},
            )
            resp.raise_for_status()
            data = resp.json()

            if "errors" in data:
                logger.error(f"GraphQL errors: {data['errors']}")
                break

            batch = data.get("data", {}).get("findings", [])
            findings.extend(batch)

            if len(batch) < limit:
                break
            offset += limit

        logger.info(f"Fetched {len(findings)} findings from Nemesis")
        return findings

    def parse_finding(self, finding: dict) -> tuple[dict, list[dict]]:
        category = finding.get("category", "")
        finding_name = finding.get("finding_name", "")

        mapping = resolve_techniques(category, finding_name)

        quarantine_entries = []
        if not mapping.techniques:
            quarantine_entries.append({
                "value": f"{category}/{finding_name}",
                "source": "nemesis",
                "reason": f"No ATT&CK mapping for Nemesis finding {category}/{finding_name}",
                "suggested_fix": None,
                "created_at": datetime.now(timezone.utc),
            })

        primary_technique = mapping.techniques[0] if mapping.techniques else None

        tags = []
        for tech_id in mapping.techniques:
            tags.append({"type": "technique_id", "value": tech_id, "quarantine_reason": None, "suggested_fix": None})
        tags.append({"type": "free_label", "value": category, "quarantine_reason": None, "suggested_fix": None})

        severity = finding.get("severity", 0)
        if severity is not None:
            tags.append({"type": "free_label", "value": f"severity:{severity}", "quarantine_reason": None, "suggested_fix": None})

        origin = finding.get("origin_name", "")
        if origin:
            tags.append({"type": "free_label", "value": f"origin:{origin}", "quarantine_reason": None, "suggested_fix": None})

        triage = finding.get("triage_value")
        if triage:
            tags.append({"type": "free_label", "value": f"triage:{triage}", "quarantine_reason": None, "suggested_fix": None})

        finding_data = finding.get("data")
        poc_ref = None
        if finding_data:
            try:
                poc_ref = json.dumps(finding_data)[:500]
            except (TypeError, ValueError):
                poc_ref = str(finding_data)[:500]

        file_info = finding.get("files_enriched")
        file_name = ""
        if file_info:
            file_name = file_info.get("file_name", "")

        row = {
            "notion_page_id": f"nemesis-{finding['id']}",
            "name": f"{finding_name} ({file_name})" if file_name else finding_name,
            "tags": tags,
            "attack_reference": primary_technique,
            "mitigation_reference": None,
            "poc_reference": poc_ref,
            "parent_project": None,
            "last_edited_at": finding.get("updated_at") or finding.get("created_at"),
        }

        return row, quarantine_entries

    def build_snapshot(self, rows: list[dict], captured_at: datetime | None = None) -> dict:
        now = captured_at or datetime.now(timezone.utc)
        snapshot_id = f"nemesis-{now.strftime('%Y-%m-%dT%H:%M:%SZ')}"

        sorted_rows = sorted(rows, key=lambda r: r.get("notion_page_id", ""))
        sha = content_hash({"rows": sorted_rows})

        return {
            "_id": snapshot_id,
            "sha256": sha,
            "rows": sorted_rows,
            "captured_at": now,
            "recorded_from": now,
            "recorded_to": None,
        }

    def fetch_snapshot(self, db=None, storage=None, since: datetime | None = None) -> dict:
        findings = self.fetch_all_findings(since=since)

        rows = []
        all_quarantine = []
        for finding in findings:
            row, quarantine_entries = self.parse_finding(finding)
            rows.append(row)
            all_quarantine.extend(quarantine_entries)

        snapshot = self.build_snapshot(rows)

        if db:
            db.overlay_snapshots.update_one(
                {"_id": snapshot["_id"]},
                {"$setOnInsert": snapshot},
                upsert=True,
            )
            for q in all_quarantine:
                db.ingest_quarantine.update_one(
                    {"source": q["source"], "value": q["value"]},
                    {"$setOnInsert": q},
                    upsert=True,
                )
            logger.info(
                f"Stored Nemesis snapshot {snapshot['_id']} with {len(rows)} findings, "
                f"{len(all_quarantine)} quarantine entries"
            )

        if storage:
            payload = json.dumps(snapshot, default=str).encode()
            storage.put_overlay_snapshot(snapshot["_id"], payload, snapshot["sha256"])

        return snapshot
