from __future__ import annotations

from datetime import datetime

from beanie import Document
from pydantic import BaseModel


class CompoundScenarioId(BaseModel):
    scenario_id: str
    rev: int


class ScenarioDoc(Document):
    id: CompoundScenarioId
    scenario_id: str
    rev: int
    is_head: bool = True
    framework_pin: str
    content_hash: str
    steps: list[dict]
    classification: dict | None = None
    created_at: datetime
    created_by: str
    recorded_from: datetime
    recorded_to: datetime | None = None

    class Settings:
        name = "scenarios"


class ScenarioAttackRefDoc(Document):
    scenario_id: str
    rev: int
    is_head: bool
    step_id: str
    stix_id: str
    release_id: str

    class Settings:
        name = "scenario_attack_refs"
