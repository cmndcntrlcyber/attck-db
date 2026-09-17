from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from loguru import logger


@dataclass
class FindingsSummary:
    diff_id: str
    total: int = 0
    technique_revoked: int = 0
    technique_deprecated: int = 0
    technique_modified: int = 0
    tactic_moved: int = 0
    auto_remap_eligible: int = 0
    affected_scenarios: list[str] = field(default_factory=list)
    affected_reports: list[str] = field(default_factory=list)


class NotificationBackend(Protocol):
    def send(self, summary: FindingsSummary) -> None: ...


class LogNotificationBackend:
    def send(self, summary: FindingsSummary) -> None:
        logger.info(
            f"Drift findings for {summary.diff_id}: "
            f"{summary.total} total, {summary.auto_remap_eligible} auto-remappable, "
            f"{len(summary.affected_scenarios)} scenarios, {len(summary.affected_reports)} reports"
        )


class NotionCommentBackend:
    def __init__(self, notion_source, db=None):
        self.notion = notion_source
        self.db = db

    def send(self, summary: FindingsSummary) -> None:
        LogNotificationBackend().send(summary)

        if not self.db:
            return

        affected_refs = set()
        for sid in summary.affected_scenarios:
            scenario = self.db.scenarios.find_one(
                {"scenario_id": sid, "is_head": True},
                {"steps": 1},
            )
            if not scenario:
                continue
            for step in scenario.get("steps", []):
                ref = step.get("attack_ref", {})
                ext_id = ref.get("external_id_at_pin", "")
                if ext_id:
                    affected_refs.add(ext_id)

        if not affected_refs:
            return

        overlay_rows = self.db.overlay_snapshots.find_one(
            {"recorded_to": None},
            sort=[("captured_at", -1)],
        )
        if not overlay_rows:
            return

        for row in overlay_rows.get("rows", []):
            attack_ref = row.get("attack_reference", "")
            if attack_ref in affected_refs:
                page_id = row.get("notion_page_id", "")
                if page_id:
                    text = (
                        f"⚠ ATT&CK drift detected ({summary.diff_id}): "
                        f"{summary.technique_revoked} revoked, "
                        f"{summary.technique_deprecated} deprecated, "
                        f"{summary.technique_modified} modified. "
                        f"{summary.auto_remap_eligible} auto-remappable. "
                        f"Affects {len(summary.affected_scenarios)} scenarios."
                    )
                    self.notion.post_comment(page_id, text)


class NotificationSink:
    def __init__(self, backend: NotificationBackend | None = None):
        self.backend = backend or LogNotificationBackend()

    def notify(self, findings: list[dict]) -> FindingsSummary:
        if not findings:
            return FindingsSummary(diff_id="")

        diff_id = findings[0].get("diff_id", "")
        summary = FindingsSummary(diff_id=diff_id)
        summary.total = len(findings)

        scenarios = set()
        reports = set()

        for f in findings:
            ft = f.get("finding", "")
            if ft == "technique_revoked":
                summary.technique_revoked += 1
            elif ft == "technique_deprecated":
                summary.technique_deprecated += 1
            elif ft == "technique_modified":
                summary.technique_modified += 1
            elif ft == "tactic_moved":
                summary.tactic_moved += 1

            if f.get("auto_remap_eligible"):
                summary.auto_remap_eligible += 1

            scenarios.add(f.get("scenario_id", ""))
            for r in f.get("affected_reports", []):
                reports.add(r)

        summary.affected_scenarios = sorted(scenarios)
        summary.affected_reports = sorted(reports)

        self.backend.send(summary)
        return summary
