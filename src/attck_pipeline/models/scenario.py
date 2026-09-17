from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class AttackRef(BaseModel):
    stix_id: str
    external_id_at_pin: str | None = None
    release_id: str


class ScenarioStep(BaseModel):
    step_id: str
    order: int
    action: str
    attack_ref: AttackRef | None = None
    overlay_ref: str | None = None


class Scenario(BaseModel):
    scenario_id: str
    rev: int
    is_head: bool = True
    framework_pin: str
    content_hash: str
    steps: list[ScenarioStep]
    classification: dict | None = None
    created_at: datetime
    created_by: str
    recorded_from: datetime
    recorded_to: datetime | None = None
