from __future__ import annotations

import re
from dataclasses import dataclass

TACTIC_ID_RE = re.compile(r"^TA\d{4}$")
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
GROUP_ID_RE = re.compile(r"^G\d{4}$")
SOFTWARE_ID_RE = re.compile(r"^S\d{4}$")

KNOWN_TACTIC_NAMES = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}

KNOWN_DOMAINS = {"Enterprise", "Mobile", "ICS"}
KNOWN_PLAN_KINDS = {"Emulation Plan", "Custom Plan"}

MALFORMED_TACTIC_RE = re.compile(r"^TA\d{1,3}$")
MALFORMED_TECHNIQUE_RE = re.compile(r"^T\d{1,3}$")
MALFORMED_SUB_RE = re.compile(r"^T\d{4}\.\d{1,2}$")
ZERO_PADDED_SUB_RE = re.compile(r"^T\d{4}\.0+$")


@dataclass
class TagResult:
    type: str
    value: str
    quarantine_reason: str | None = None
    suggested_fix: str | None = None


class TagNormalizer:
    def normalize(self, tag: str) -> TagResult:
        tag = tag.strip()

        if TACTIC_ID_RE.match(tag):
            return TagResult(type="tactic_id", value=tag)

        if TECHNIQUE_ID_RE.match(tag):
            return TagResult(type="technique_id", value=tag)

        if GROUP_ID_RE.match(tag):
            return TagResult(type="group_id", value=tag)

        if SOFTWARE_ID_RE.match(tag):
            return TagResult(type="software_id", value=tag)

        if tag.lower() in KNOWN_TACTIC_NAMES:
            return TagResult(type="tactic_shortname", value=tag.lower())

        if tag in KNOWN_DOMAINS:
            return TagResult(type="domain", value=tag)

        if tag in KNOWN_PLAN_KINDS:
            return TagResult(type="plan_kind", value=tag)

        fix = self._suggest_fix(tag)
        if fix is not None:
            return TagResult(
                type="quarantine",
                value=tag,
                quarantine_reason=f"Malformed identifier '{tag}'",
                suggested_fix=fix,
            )

        if MALFORMED_TECHNIQUE_RE.match(tag):
            return TagResult(
                type="quarantine",
                value=tag,
                quarantine_reason=f"Malformed technique ID '{tag}' — too few digits or possible custom technique",
                suggested_fix=None,
            )

        return TagResult(type="free_label", value=tag)

    def _suggest_fix(self, tag: str) -> str | None:
        if ZERO_PADDED_SUB_RE.match(tag):
            base = tag.split(".")[0]
            return base

        if MALFORMED_SUB_RE.match(tag):
            parts = tag.split(".")
            base = parts[0]
            sub = parts[1].zfill(3)
            return f"{base}.{sub}"

        if MALFORMED_TACTIC_RE.match(tag):
            digits = tag[2:]
            return f"TA{digits.zfill(4)}"

        return None
