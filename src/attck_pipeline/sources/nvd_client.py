from __future__ import annotations

import time

import httpx
from loguru import logger

from attck_pipeline.config import Settings


class NvdClient:
    def __init__(self, settings: Settings | None = None, client: httpx.Client | None = None):
        self.settings = settings or Settings()
        self._client = client
        self._last_request_at: float = 0.0

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            headers = {"Content-Type": "application/json"}
            if self.settings.nvd_api_key:
                headers["apiKey"] = self.settings.nvd_api_key
            self._client = httpx.Client(
                base_url=self.settings.nvd_base_url,
                headers=headers,
                timeout=30.0,
            )
        return self._client

    def _rate_limit(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        delay = self.settings.nvd_rate_limit_seconds
        if self.settings.nvd_api_key:
            delay = max(0.1, delay / 5)
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request_at = time.monotonic()

    def get_cwe_ids(self, cve_id: str) -> list[str]:
        self._rate_limit()
        try:
            resp = self.client.get(f"/cves/2.0", params={"cveId": cve_id})
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning(f"NVD lookup failed for {cve_id}: {exc}")
            return []

        data = resp.json()
        cwe_ids = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    value = desc.get("value", "")
                    if value.startswith("CWE-") and value != "CWE-noinfo":
                        cwe_ids.append(value)

        cwe_ids = sorted(set(cwe_ids))
        logger.debug(f"NVD {cve_id} -> CWE: {cwe_ids}")
        return cwe_ids

    def get_cve_metadata(self, cve_id: str) -> dict | None:
        self._rate_limit()
        try:
            resp = self.client.get(f"/cves/2.0", params={"cveId": cve_id})
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning(f"NVD metadata lookup failed for {cve_id}: {exc}")
            return None

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_data = vulns[0].get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        en_desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)

        metrics = cve_data.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])
        cvss_score = cvss_v31[0].get("cvssData", {}).get("baseScore") if cvss_v31 else None

        return {
            "cve_id": cve_id,
            "description": en_desc,
            "cvss_score": cvss_score,
            "published": cve_data.get("published"),
            "last_modified": cve_data.get("lastModified"),
        }
