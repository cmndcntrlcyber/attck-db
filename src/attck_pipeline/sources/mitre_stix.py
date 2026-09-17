from __future__ import annotations

from dataclasses import dataclass

import httpx
from loguru import logger

from attck_pipeline.canonical import bundle_hash
from attck_pipeline.config import Settings

DOMAINS = ["enterprise-attack", "mobile-attack", "ics-attack"]


@dataclass
class VersionInfo:
    domain: str
    version: str
    url: str
    predecessor: str | None = None


class MitreStixSource:
    def __init__(self, settings: Settings | None = None, client: httpx.Client | None = None):
        self.settings = settings or Settings()
        self.client = client or httpx.Client(timeout=120.0)
        self.base_url = f"https://raw.githubusercontent.com/{self.settings.stix_data_repo}/{self.settings.stix_data_branch}"

    def fetch_index(self) -> dict:
        url = f"{self.base_url}/index.json"
        logger.info(f"Fetching STIX index from {url}")
        resp = self.client.get(url)
        resp.raise_for_status()
        return resp.json()

    def list_versions(self, index: dict, domain: str) -> list[VersionInfo]:
        collections = index.get("collections", [])
        domain_collection = None
        for c in collections:
            if c.get("id", "").startswith(f"x-mitre-collection--") and domain in c.get("name", "").lower().replace(" ", "-"):
                domain_collection = c
                break

        if not domain_collection:
            for c in collections:
                versions = c.get("versions", [])
                if versions and domain in versions[0].get("url", ""):
                    domain_collection = c
                    break

        if not domain_collection:
            return []

        versions_raw = domain_collection.get("versions", [])
        versions = []
        for i, v in enumerate(versions_raw):
            ver = v.get("version", "")
            url = v.get("url", "")
            if not url:
                url = f"{self.base_url}/{domain}/{domain}-{ver}.json"
            predecessor = versions_raw[i + 1]["version"] if i + 1 < len(versions_raw) else None
            versions.append(VersionInfo(
                domain=domain,
                version=ver,
                url=url,
                predecessor=predecessor,
            ))

        return versions

    def fetch_bundle(self, domain: str, version: str) -> tuple[bytes, str]:
        url = f"{self.base_url}/{domain}/{domain}-{version}.json"
        logger.info(f"Fetching STIX bundle from {url}")
        resp = self.client.get(url)
        resp.raise_for_status()
        raw = resp.content
        sha = bundle_hash(raw)
        return raw, sha
