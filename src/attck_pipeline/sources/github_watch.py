from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx
from loguru import logger

from attck_pipeline.config import Settings


@dataclass
class NewRelease:
    domain: str
    version: str
    tag: str
    published_at: str


class GitHubReleaseWatcher:
    def __init__(self, settings: Settings | None = None, client: httpx.Client | None = None):
        self.settings = settings or Settings()
        headers = {"Accept": "application/vnd.github+json"}
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"
        self.client = client or httpx.Client(timeout=30.0, headers=headers)
        self.api_base = f"https://api.github.com/repos/{self.settings.stix_data_repo}"

    def check_for_new_releases(self, known_tags: set[str]) -> list[NewRelease]:
        url = f"{self.api_base}/releases"
        resp = self.client.get(url, params={"per_page": 50})
        resp.raise_for_status()

        releases = resp.json()
        new_releases = []

        for release in releases:
            tag = release.get("tag_name", "")
            if tag in known_tags:
                continue

            published = release.get("published_at", "")
            parsed = self._parse_tag(tag)
            if parsed:
                for domain, version in parsed:
                    new_releases.append(NewRelease(
                        domain=domain,
                        version=version,
                        tag=tag,
                        published_at=published,
                    ))

        return new_releases

    def get_known_tags(self, db) -> set[str]:
        """Build set of tags we've already ingested from framework_releases."""
        tags = set()
        for release in db.framework_releases.find({}, {"_id": 1, "version": 1, "domain": 1}):
            tags.add(f"v{release['version']}")
            tags.add(release["version"])
        return tags

    def fetch_index(self) -> dict:
        """Fetch the STIX data repo index.json for version discovery."""
        url = f"https://raw.githubusercontent.com/{self.settings.stix_data_repo}/{self.settings.stix_data_branch}/index.json"
        resp = self.client.get(url)
        resp.raise_for_status()
        return resp.json()

    def discover_new_versions(self, db) -> list[NewRelease]:
        """Compare index.json versions against what's already ingested."""
        index = self.fetch_index()
        new_releases = []

        for collection in index.get("collections", []):
            domain = self._domain_from_collection(collection)
            if not domain or domain not in self.settings.watch_domains:
                continue

            for ver_entry in collection.get("versions", []):
                version = ver_entry.get("version", "")
                release_id = f"{domain}@{version}"
                if not db.framework_releases.find_one({"_id": release_id}):
                    new_releases.append(NewRelease(
                        domain=domain,
                        version=version,
                        tag=f"v{version}",
                        published_at=ver_entry.get("modified", ""),
                    ))

        return new_releases

    def _parse_tag(self, tag: str) -> list[tuple[str, str]] | None:
        """Parse a GitHub release tag into (domain, version) pairs."""
        clean = tag.lstrip("v")
        results = []
        for domain in self.settings.watch_domains:
            if domain in tag:
                version = tag.replace(f"{domain}-", "").lstrip("v")
                results.append((domain, version))
                return results

        try:
            parts = clean.split(".")
            if len(parts) >= 2 and parts[0].isdigit():
                for domain in self.settings.watch_domains:
                    results.append((domain, clean))
                return results
        except (ValueError, IndexError):
            pass

        return None

    @staticmethod
    def _domain_from_collection(collection: dict) -> str | None:
        name = collection.get("name", "").lower().replace(" ", "-")
        for domain in ("enterprise-attack", "mobile-attack", "ics-attack"):
            if domain in name:
                return domain
        versions = collection.get("versions", [])
        if versions:
            url = versions[0].get("url", "")
            for domain in ("enterprise-attack", "mobile-attack", "ics-attack"):
                if domain in url:
                    return domain
        return None


def run_watch_loop(settings: Settings, db, secure_db, storage=None):
    """Blocking poll loop that checks for new releases and ingests them."""
    from attck_pipeline.diff.engine import DiffEngine
    from attck_pipeline.impact.drift import DriftDetector
    from attck_pipeline.impact.notify import NotificationSink
    from attck_pipeline.ingest.lineage import LineageBuilder
    from attck_pipeline.ingest.loader import StixLoader
    from attck_pipeline.sources.mitre_stix import MitreStixSource

    watcher = GitHubReleaseWatcher(settings)
    stix_source = MitreStixSource(settings)
    loader = StixLoader(db, storage=storage)
    lineage_builder = LineageBuilder(db)
    diff_engine = DiffEngine(db)
    drift_detector = DriftDetector(db, secure_db)
    notifier = NotificationSink()

    logger.info(f"Starting release watch loop (interval={settings.watch_interval_seconds}s)")

    while True:
        try:
            new_releases = watcher.discover_new_versions(db)

            if not new_releases:
                logger.info("No new releases found")
            else:
                logger.info(f"Found {len(new_releases)} new releases")

            for release in sorted(new_releases, key=lambda r: r.version):
                logger.info(f"Ingesting {release.domain}@{release.version}")

                raw_bytes, sha256 = stix_source.fetch_bundle(release.domain, release.version)

                import json
                bundle = json.loads(raw_bytes)

                run_id, relationships = loader.load_release(
                    domain=release.domain,
                    version=release.version,
                    raw_bytes=raw_bytes,
                    source_uri=f"mitre-attack/attack-stix-data/{release.domain}/{release.domain}-{release.version}.json",
                )

                release_id = f"{release.domain}@{release.version}"
                lineage_builder.build_edges(release_id, bundle.get("objects", []))

                predecessor = db.framework_releases.find_one(
                    {"_id": release_id},
                    {"predecessor": 1},
                )
                pred_id = predecessor.get("predecessor") if predecessor else None

                if pred_id:
                    diff_doc = diff_engine.compute_diff(pred_id, release_id)

                    from pymongo import MongoClient
                    client = MongoClient(settings.mongo_uri)
                    diff_engine.seal_release(client, release_id, diff_doc)
                    client.close()

                    findings = drift_detector.detect_impact(diff_doc)
                    if findings:
                        notifier.notify(findings)

                logger.info(f"Completed ingest for {release.domain}@{release.version}")

        except Exception as e:
            logger.error(f"Watch loop error: {e}")

        logger.info(f"Sleeping {settings.watch_interval_seconds}s until next check")
        time.sleep(settings.watch_interval_seconds)
