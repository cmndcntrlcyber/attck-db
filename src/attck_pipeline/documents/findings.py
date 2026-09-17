from __future__ import annotations

from typing import Literal

from beanie import Document
from pydantic import ConfigDict, Field


class DriftFindingDoc(Document):
    diff_id: str
    scenario_id: str
    scenario_rev: int
    step_id: str
    finding: Literal["technique_revoked", "technique_deprecated", "technique_modified", "tactic_moved"]
    from_ref: dict = Field(alias="from")
    proposed: list[dict] = []
    auto_remap_eligible: bool = False
    affected_reports: list[str] = []
    status: Literal["open", "accepted", "overridden", "dismissed"] = "open"
    resolution: dict | None = None

    model_config = ConfigDict(populate_by_name=True)

    class Settings:
        name = "drift_findings"
