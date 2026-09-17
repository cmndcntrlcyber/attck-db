from __future__ import annotations

from typing import Literal

from beanie import Document
from pydantic import BaseModel, ConfigDict, Field


class CompoundMemberId(BaseModel):
    r: str
    s: str


class ReleaseMemberDoc(Document):
    id: CompoundMemberId
    release_id: str
    stix_id: str
    external_id: str | None = None
    object_hash: str
    state: Literal["active", "revoked", "deprecated"]

    class Settings:
        name = "release_members"


class EdgeEndpoint(BaseModel):
    stix_id: str
    external_id: str | None = None


class IdentityEdgeDoc(Document):
    release_id: str
    kind: Literal["revoked_by", "subtechnique_of", "deprecated_no_successor", "split_into", "merged_into"]
    from_endpoint: EdgeEndpoint = Field(alias="from")
    to_endpoint: EdgeEndpoint | None = Field(default=None, alias="to")
    evidence: dict
    confidence: float

    model_config = ConfigDict(populate_by_name=True)

    class Settings:
        name = "identity_edges"
