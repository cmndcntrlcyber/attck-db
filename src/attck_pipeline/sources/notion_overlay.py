from __future__ import annotations

import re
from datetime import datetime, timezone

import httpx
from loguru import logger

from attck_pipeline.canonical import content_hash
from attck_pipeline.config import Settings
from attck_pipeline.sources.tag_normalizer import TagNormalizer, TagResult

TECHNIQUE_URL_RE = re.compile(r"/techniques/(T\d{4})(?:/(\d{3}))?/?")
NOTION_API_BASE = "https://api.notion.com/v1"
NOTION_API_VERSION = "2022-06-28"


class NotionOverlaySource:
    def __init__(self, settings: Settings | None = None, collection_id: str | None = None):
        self.settings = settings or Settings()
        self.collection_id = collection_id or self.settings.notion_collection_id
        self.tag_normalizer = TagNormalizer()
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(
                base_url=NOTION_API_BASE,
                headers={
                    "Authorization": f"Bearer {self.settings.notion_token}",
                    "Notion-Version": NOTION_API_VERSION,
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    def fetch_all_pages(self) -> list[dict]:
        """Fetch all pages from the Notion database (handles pagination)."""
        pages = []
        has_more = True
        start_cursor = None

        while has_more:
            body: dict = {}
            if start_cursor:
                body["start_cursor"] = start_cursor

            resp = self.client.post(
                f"/databases/{self.collection_id}/query",
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

            pages.extend(data.get("results", []))
            has_more = data.get("has_more", False)
            start_cursor = data.get("next_cursor")

        logger.info(f"Fetched {len(pages)} pages from Notion database {self.collection_id}")
        return pages

    def fetch_snapshot(self, db=None, storage=None) -> dict:
        """Fetch a full snapshot from the Notion API, parse rows, store quarantine entries."""
        pages = self.fetch_all_pages()

        rows = []
        quarantine = []
        for page in pages:
            row = self.parse_row(page)
            rows.append(row)
            for tag in row.get("tags", []):
                if tag.get("type") == "quarantine":
                    quarantine.append({
                        "value": tag["value"],
                        "source": "notion_overlay",
                        "reason": tag.get("quarantine_reason", ""),
                        "suggested_fix": tag.get("suggested_fix"),
                        "created_at": datetime.now(timezone.utc),
                    })

        snapshot = self.build_snapshot(rows)

        if db:
            db.overlay_snapshots.update_one(
                {"_id": snapshot["_id"]},
                {"$setOnInsert": snapshot},
                upsert=True,
            )
            for q in quarantine:
                db.ingest_quarantine.update_one(
                    {"source": q["source"], "value": q["value"]},
                    {"$setOnInsert": q},
                    upsert=True,
                )
            logger.info(f"Stored snapshot {snapshot['_id']} with {len(quarantine)} quarantine entries")

        if storage:
            import json
            payload = json.dumps(snapshot, default=str).encode()
            storage.put_overlay_snapshot(snapshot["_id"], payload, snapshot["sha256"])

        return snapshot

    def post_comment(self, page_id: str, text: str) -> dict | None:
        """Post a comment on a Notion page (for drift finding notifications)."""
        body = {
            "parent": {"page_id": page_id},
            "rich_text": [
                {
                    "type": "text",
                    "text": {"content": text},
                }
            ],
        }
        try:
            resp = self.client.post("/comments", json=body)
            resp.raise_for_status()
            logger.info(f"Posted comment on page {page_id}")
            return resp.json()
        except Exception as e:
            logger.error(f"Failed to post comment on page {page_id}: {e}")
            return None

    def parse_row(self, notion_page: dict) -> dict:
        props = notion_page.get("properties", {})

        name = self._extract_title(props.get("Name", {}))
        raw_tags = self._extract_multi_select(props.get("Tags", {}))
        attack_url = self._extract_url(props.get("MITRE ATT&CK Reference", {}))
        mitigation_url = self._extract_url(props.get("Mitigation", {}))
        poc_ref = self._extract_text(props.get("POC Reference", {}))
        parent_project = self._extract_url(props.get("Parent Project", {}))
        last_edited = props.get("Time of Change", {}).get("last_edited_time")

        tags = [self.tag_normalizer.normalize(t) for t in raw_tags]
        attack_ref = self._resolve_reference_url(attack_url) if attack_url else None

        return {
            "notion_page_id": notion_page.get("id", ""),
            "name": name,
            "tags": [
                {
                    "type": t.type,
                    "value": t.value,
                    "quarantine_reason": t.quarantine_reason,
                    "suggested_fix": t.suggested_fix,
                }
                for t in tags
            ],
            "attack_reference": attack_ref,
            "mitigation_reference": mitigation_url,
            "poc_reference": poc_ref,
            "parent_project": parent_project,
            "last_edited_at": last_edited,
        }

    def build_snapshot(self, rows: list[dict], captured_at: datetime | None = None) -> dict:
        now = captured_at or datetime.now(timezone.utc)
        snapshot_id = f"notion-{now.strftime('%Y-%m-%dT%H:%M:%SZ')}"

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

    @staticmethod
    def _resolve_reference_url(url: str) -> str | None:
        match = TECHNIQUE_URL_RE.search(url)
        if not match:
            return None
        base = match.group(1)
        sub = match.group(2)
        if sub:
            return f"{base}.{sub}"
        return base

    @staticmethod
    def _extract_title(prop: dict) -> str:
        title_list = prop.get("title", [])
        return "".join(t.get("plain_text", "") for t in title_list)

    @staticmethod
    def _extract_multi_select(prop: dict) -> list[str]:
        return [opt["name"] for opt in prop.get("multi_select", [])]

    @staticmethod
    def _extract_url(prop: dict) -> str | None:
        return prop.get("url")

    @staticmethod
    def _extract_text(prop: dict) -> str | None:
        rich = prop.get("rich_text", [])
        if not rich:
            return None
        return "".join(t.get("plain_text", "") for t in rich)
