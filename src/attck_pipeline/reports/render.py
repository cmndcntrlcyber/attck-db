from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger
from pymongo.database import Database

from attck_pipeline.canonical import canonical_bytes

TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportRenderer:
    def __init__(self, db: Database, secure_db: Database, storage=None):
        self.db = db
        self.secure_db = secure_db
        self.storage = storage

    def render(self, report_doc: dict) -> dict:
        manifest = report_doc["manifest"]
        dataset = self._materialize_dataset(manifest)

        render_params = manifest.get("render_params", {})
        source_date_epoch = render_params.get("source_date_epoch", 0)
        report_time = datetime.fromtimestamp(source_date_epoch, tz=timezone.utc)
        fmt = render_params.get("format", "json")

        payload = {
            "report_id": report_doc["_id"],
            "generated_at": report_time.isoformat(),
            "manifest_sha256": report_doc["manifest_sha256"],
            "framework_release": manifest["framework_release"],
            "scenarios": dataset["scenarios"],
            "techniques": dataset["techniques"],
            "overlay": dataset.get("overlay"),
        }

        payload_bytes = canonical_bytes(payload)
        payload_sha256 = "sha256:" + hashlib.sha256(payload_bytes).hexdigest()

        result = {
            "payload": payload,
            "payload_bytes": payload_bytes,
            "payload_sha256": payload_sha256,
            "format": fmt,
        }

        if fmt in ("html", "pdf"):
            html_bytes = self._render_html(payload)
            result["html_bytes"] = html_bytes
            result["html_sha256"] = "sha256:" + hashlib.sha256(html_bytes).hexdigest()

            if fmt == "pdf":
                pdf_bytes = self._render_pdf(html_bytes, report_doc["_id"], report_doc["manifest_sha256"])
                result["pdf_bytes"] = pdf_bytes
                result["pdf_sha256"] = "sha256:" + hashlib.sha256(pdf_bytes).hexdigest()

        if self.storage:
            if fmt == "pdf" and "pdf_bytes" in result:
                stored = self.storage.put_report(
                    report_doc["_id"], result["pdf_bytes"], result["pdf_sha256"], fmt="pdf",
                )
            elif fmt == "html" and "html_bytes" in result:
                stored = self.storage.put_report(
                    report_doc["_id"], result["html_bytes"], result["html_sha256"], fmt="html",
                )
            else:
                stored = self.storage.put_report(
                    report_doc["_id"], payload_bytes, payload_sha256, fmt="json",
                )
            result["blob_ref"] = self.storage.blob_ref(stored.bucket, stored.key)

        return result

    def _render_html(self, payload: dict) -> bytes:
        from jinja2 import Environment, FileSystemLoader

        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        template = env.get_template("report.html.j2")
        html = template.render(**payload)
        return html.encode("utf-8")

    def _render_pdf(self, html_bytes: bytes, report_id: str, manifest_sha256: str) -> bytes:
        from weasyprint import HTML

        doc = HTML(string=html_bytes.decode("utf-8"))
        pdf_bytes = doc.write_pdf()
        return pdf_bytes

    def _materialize_dataset(self, manifest: dict) -> dict:
        release_id = manifest["framework_release"]

        members = list(
            self.db.release_members.find(
                {"release_id": release_id},
            ).sort([("stix_id", 1)])
        )

        technique_hashes = [m["object_hash"] for m in members]
        techniques = list(
            self.db.attack_objects.find(
                {"_id": {"$in": technique_hashes}},
            ).sort([("_id", 1)])
        )
        for t in techniques:
            t.pop("raw", None)

        scenarios = []
        for pin in sorted(manifest.get("scenario_set", []), key=lambda s: (s["scenario_id"], s["rev"])):
            scenario = self.secure_db.scenarios.find_one({
                "_id": {"scenario_id": pin["scenario_id"], "rev": pin["rev"]},
            })
            if scenario:
                scenario.pop("raw", None)
                scenarios.append(scenario)

        overlay = None
        overlay_ref = manifest.get("overlay_snapshot")
        if overlay_ref:
            snap = self.db.overlay_snapshots.find_one({"_id": overlay_ref["snapshot_id"]})
            if snap:
                overlay = snap

        return {
            "techniques": techniques,
            "scenarios": scenarios,
            "overlay": overlay,
        }
