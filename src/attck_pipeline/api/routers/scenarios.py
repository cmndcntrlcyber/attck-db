from __future__ import annotations

from fastapi import APIRouter, HTTPException

from attck_pipeline.documents.scenarios import ScenarioDoc

router = APIRouter()


@router.get("/{scenario_id}")
async def get_scenario(scenario_id: str, include_history: bool = False):
    if include_history:
        revisions = await ScenarioDoc.find(
            ScenarioDoc.scenario_id == scenario_id,
        ).sort("-rev").to_list()
        if not revisions:
            raise HTTPException(404, detail=f"Scenario {scenario_id} not found")
        return {"scenario_id": scenario_id, "head": revisions[0], "revisions": revisions}

    head = await ScenarioDoc.find_one(
        ScenarioDoc.scenario_id == scenario_id,
        ScenarioDoc.is_head == True,  # noqa: E712
    )
    if not head:
        raise HTTPException(404, detail=f"Scenario {scenario_id} not found")
    return head
