from attck_pipeline.documents.releases import FrameworkReleaseDoc
from attck_pipeline.documents.objects import AttackObjectDoc
from attck_pipeline.documents.members import ReleaseMemberDoc, IdentityEdgeDoc
from attck_pipeline.documents.diffs import ReleaseDiffDoc
from attck_pipeline.documents.scenarios import ScenarioDoc, ScenarioAttackRefDoc
from attck_pipeline.documents.findings import DriftFindingDoc
from attck_pipeline.documents.reports import ReportDoc
from attck_pipeline.documents.overlays import OverlaySnapshotDoc
from attck_pipeline.documents.ingest import IngestQuarantineDoc, IngestRunDoc

PUBLIC_DOCUMENTS = [
    FrameworkReleaseDoc,
    AttackObjectDoc,
    ReleaseMemberDoc,
    IdentityEdgeDoc,
    ReleaseDiffDoc,
    OverlaySnapshotDoc,
    IngestQuarantineDoc,
    IngestRunDoc,
]

SECURE_DOCUMENTS = [
    ScenarioDoc,
    ScenarioAttackRefDoc,
    DriftFindingDoc,
    ReportDoc,
]
