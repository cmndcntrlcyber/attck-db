import json
from datetime import datetime, timezone

from attck_pipeline.sources.nemesis_source import NemesisSource


MOCK_FINDINGS = [
    {
        "id": "f001",
        "finding_name": "chromium_logins",
        "category": "CREDENTIAL",
        "severity": 8,
        "origin_type": "file",
        "origin_name": "workstation-01",
        "data": {"username": "admin", "url": "https://internal.corp"},
        "triage_value": "true_positive",
        "created_at": "2026-09-15T10:00:00Z",
        "updated_at": "2026-09-15T12:00:00Z",
        "files_enriched": {
            "file_name": "Login Data",
            "extension": "",
            "hashes": {"sha256": "abc123"},
            "object_id": "obj-001",
        },
    },
    {
        "id": "f002",
        "finding_name": "ntlm_hash",
        "category": "EXTRACTED_HASH",
        "severity": 9,
        "origin_type": "file",
        "origin_name": "dc-01",
        "data": {"hash": "aad3b435b51404eeaad3b435b51404ee:..."},
        "triage_value": None,
        "created_at": "2026-09-15T11:00:00Z",
        "updated_at": "2026-09-15T11:30:00Z",
        "files_enriched": {
            "file_name": "ntds.dit",
            "extension": ".dit",
            "hashes": {"sha256": "def456"},
            "object_id": "obj-002",
        },
    },
    {
        "id": "f003",
        "finding_name": "custom_yara_rule",
        "category": "YARA_MATCH",
        "severity": 3,
        "origin_type": "file",
        "origin_name": "server-05",
        "data": {"rule": "suspicious_strings"},
        "triage_value": None,
        "created_at": "2026-09-15T12:00:00Z",
        "updated_at": "2026-09-15T12:00:00Z",
        "files_enriched": None,
    },
]


class TestNemesisSourceParsing:
    def setup_method(self):
        self.source = NemesisSource()

    def test_parse_chromium_login_finding(self):
        row, quarantine = self.source.parse_finding(MOCK_FINDINGS[0])

        assert row["notion_page_id"] == "nemesis-f001"
        assert "Login Data" in row["name"]
        assert row["attack_reference"] == "T1555.003"
        assert any(t["value"] == "T1555.003" for t in row["tags"])
        assert any(t["value"] == "CREDENTIAL" for t in row["tags"])
        assert any(t["value"] == "severity:8" for t in row["tags"])
        assert any(t["value"] == "triage:true_positive" for t in row["tags"])
        assert row["poc_reference"] is not None
        assert len(quarantine) == 0

    def test_parse_ntlm_hash_finding(self):
        row, quarantine = self.source.parse_finding(MOCK_FINDINGS[1])

        assert row["notion_page_id"] == "nemesis-f002"
        assert row["attack_reference"] == "T1003.001"
        assert any(t["value"] == "T1003.001" for t in row["tags"])
        assert len(quarantine) == 0

    def test_parse_unmapped_finding_produces_quarantine(self):
        row, quarantine = self.source.parse_finding(MOCK_FINDINGS[2])

        assert row["notion_page_id"] == "nemesis-f003"
        assert row["attack_reference"] is None
        assert len(quarantine) == 1
        assert quarantine[0]["source"] == "nemesis"
        assert "YARA_MATCH/custom_yara_rule" in quarantine[0]["value"]

    def test_build_snapshot_content_hashed(self):
        rows = []
        for f in MOCK_FINDINGS:
            row, _ = self.source.parse_finding(f)
            rows.append(row)

        now = datetime(2026, 9, 15, 15, 0, 0, tzinfo=timezone.utc)
        snapshot = self.source.build_snapshot(rows, captured_at=now)

        assert snapshot["_id"] == "nemesis-2026-09-15T15:00:00Z"
        assert snapshot["sha256"].startswith("sha256:")
        assert len(snapshot["rows"]) == 3
        assert snapshot["captured_at"] == now
        assert snapshot["recorded_to"] is None

    def test_snapshot_hash_deterministic(self):
        rows = []
        for f in MOCK_FINDINGS:
            row, _ = self.source.parse_finding(f)
            rows.append(row)

        now = datetime(2026, 9, 15, 15, 0, 0, tzinfo=timezone.utc)
        snap1 = self.source.build_snapshot(rows, captured_at=now)
        snap2 = self.source.build_snapshot(rows, captured_at=now)

        assert snap1["sha256"] == snap2["sha256"]

    def test_snapshot_rows_sorted_by_id(self):
        rows = []
        for f in reversed(MOCK_FINDINGS):
            row, _ = self.source.parse_finding(f)
            rows.append(row)

        snapshot = self.source.build_snapshot(rows)
        ids = [r["notion_page_id"] for r in snapshot["rows"]]
        assert ids == sorted(ids)

    def test_parse_finding_without_file_info(self):
        row, _ = self.source.parse_finding(MOCK_FINDINGS[2])
        assert row["name"] == "custom_yara_rule"

    def test_parse_finding_truncates_poc_reference(self):
        big_finding = {
            **MOCK_FINDINGS[0],
            "data": {"key": "x" * 1000},
        }
        row, _ = self.source.parse_finding(big_finding)
        assert len(row["poc_reference"]) <= 500
