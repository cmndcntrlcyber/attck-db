from __future__ import annotations

from datetime import datetime, timezone

from pymongo.database import Database

from attck_pipeline.canonical import content_hash


class ScenarioRevisionManager:
    def __init__(self, secure_db: Database):
        self.secure_db = secure_db

    def create_revision(
        self,
        scenario_id: str,
        new_steps: list[dict],
        new_framework_pin: str,
        created_by: str = "system",
        classification: dict | None = None,
        session=None,
    ) -> int:
        now = datetime.now(timezone.utc)

        find_kwargs = {"scenario_id": scenario_id, "is_head": True}
        current_head = self.secure_db.scenarios.find_one(find_kwargs)

        if current_head is None:
            raise ValueError(f"No head revision found for scenario {scenario_id}")

        current_rev = current_head["rev"]
        new_rev = current_rev + 1

        self.secure_db.scenarios.update_one(
            {"scenario_id": scenario_id, "rev": current_rev, "is_head": True},
            {"$set": {"is_head": False, "recorded_to": now}},
        )

        new_content = {
            "scenario_id": scenario_id,
            "steps": new_steps,
            "framework_pin": new_framework_pin,
        }
        new_hash = content_hash(new_content)

        new_doc = {
            "_id": {"scenario_id": scenario_id, "rev": new_rev},
            "scenario_id": scenario_id,
            "rev": new_rev,
            "is_head": True,
            "framework_pin": new_framework_pin,
            "content_hash": new_hash,
            "steps": new_steps,
            "classification": classification or current_head.get("classification", {}),
            "created_at": now,
            "created_by": created_by,
            "recorded_from": now,
            "recorded_to": None,
        }

        self.secure_db.scenarios.insert_one(new_doc)

        self._rebuild_attack_refs(scenario_id, new_rev, new_steps, new_framework_pin)

        self.secure_db.scenario_attack_refs.update_many(
            {"scenario_id": scenario_id, "rev": current_rev},
            {"$set": {"is_head": False}},
        )

        return new_rev

    def _rebuild_attack_refs(
        self,
        scenario_id: str,
        rev: int,
        steps: list[dict],
        framework_pin: str,
    ) -> None:
        refs = []
        for step in steps:
            attack_ref = step.get("attack_ref")
            if not attack_ref:
                continue
            refs.append({
                "scenario_id": scenario_id,
                "rev": rev,
                "is_head": True,
                "step_id": step.get("step_id", ""),
                "stix_id": attack_ref.get("stix_id", ""),
                "release_id": attack_ref.get("release_id", framework_pin),
            })

        if refs:
            self.secure_db.scenario_attack_refs.insert_many(refs)
