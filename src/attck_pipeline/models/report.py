from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class QuerySpec(BaseModel):
    name: str
    version: str
    sha256: str


class TemplateRef(BaseModel):
    repo: str
    git_sha: str


class RendererRef(BaseModel):
    image: str
    lockfile_sha256: str


class RenderParams(BaseModel):
    format: str = "pdf"
    locale: str = "en_US"
    tz: str = "UTC"
    source_date_epoch: int


class ScenarioPin(BaseModel):
    scenario_id: str
    rev: int
    content_hash: str


class ReportManifest(BaseModel):
    framework_release: str
    framework_bundle_sha256: str
    scenario_set: list[ScenarioPin]
    overlay_snapshot: dict | None = None
    query_spec: QuerySpec
    template: TemplateRef
    renderer: RendererRef
    render_params: RenderParams
