from __future__ import annotations

import re
from dataclasses import dataclass, field

FINDING_TECHNIQUE_MAP: dict[tuple[str, str], list[str]] = {
    # CREDENTIAL findings
    ("CREDENTIAL", "parsed_credentials"): ["T1003"],
    ("CREDENTIAL", "chromium_logins"): ["T1555.003"],
    ("CREDENTIAL", "chromium_cookies"): ["T1539"],
    ("CREDENTIAL", "chromium_state_keys"): ["T1555.003"],
    ("CREDENTIAL", "dpapi_masterkey"): ["T1555.004"],
    ("CREDENTIAL", "dpapi_domain_backup_key"): ["T1555.004"],
    ("CREDENTIAL", "dpapi_credential"): ["T1555.004"],
    ("CREDENTIAL", "git_credentials"): ["T1552.001"],
    ("CREDENTIAL", "gpp_passwords"): ["T1552.006"],
    ("CREDENTIAL", "ssh_private_key"): ["T1552.004"],
    ("CREDENTIAL", "aws_credentials"): ["T1552.001"],
    ("CREDENTIAL", "azure_credentials"): ["T1552.001"],
    ("CREDENTIAL", "keepass_database"): ["T1555.005"],
    ("CREDENTIAL", "wifi_credentials"): ["T1552.001"],
    ("CREDENTIAL", "rdp_credentials"): ["T1552.001"],
    ("CREDENTIAL", "vnc_credentials"): ["T1552.001"],
    # EXTRACTED_HASH findings
    ("EXTRACTED_HASH", "ntlm_hash"): ["T1003.001"],
    ("EXTRACTED_HASH", "lm_hash"): ["T1003.001"],
    ("EXTRACTED_HASH", "kerberos_ticket"): ["T1558"],
    ("EXTRACTED_HASH", "dcc2_hash"): ["T1003.004"],
    ("EXTRACTED_HASH", "netntlmv2_hash"): ["T1557.001"],
    ("EXTRACTED_HASH", "sha512_crypt"): ["T1003"],
    # EXTRACTED_DATA findings
    ("EXTRACTED_DATA", "keytab"): ["T1558"],
    ("EXTRACTED_DATA", "certificate"): ["T1552.004", "T1649"],
    ("EXTRACTED_DATA", "registry_hive"): ["T1003.002"],
    ("EXTRACTED_DATA", "sam_database"): ["T1003.002"],
    ("EXTRACTED_DATA", "ntds_dit"): ["T1003.003"],
    ("EXTRACTED_DATA", "lsass_dump"): ["T1003.001"],
    ("EXTRACTED_DATA", "memory_dump"): ["T1003"],
    # Category-level fallbacks (matched when no specific finding_name matches)
    ("CREDENTIAL", "*"): ["T1552"],
    ("EXTRACTED_HASH", "*"): ["T1003"],
    ("EXTRACTED_DATA", "*"): ["T1005"],
    ("PII", "*"): ["T1530"],
}

_PREFIX_PATTERNS: list[tuple[str, str, list[str]]] = [
    ("CREDENTIAL", "dpapi_", ["T1555.004"]),
    ("CREDENTIAL", "chromium_", ["T1555.003"]),
]


@dataclass
class MappingResult:
    category: str
    finding_name: str
    techniques: list[str] = field(default_factory=list)
    match_type: str = "none"


def resolve_techniques(category: str, finding_name: str) -> MappingResult:
    exact_key = (category, finding_name)
    if exact_key in FINDING_TECHNIQUE_MAP:
        return MappingResult(
            category=category,
            finding_name=finding_name,
            techniques=FINDING_TECHNIQUE_MAP[exact_key],
            match_type="exact",
        )

    for cat, prefix, techniques in _PREFIX_PATTERNS:
        if category == cat and finding_name.startswith(prefix):
            return MappingResult(
                category=category,
                finding_name=finding_name,
                techniques=techniques,
                match_type="prefix",
            )

    wildcard_key = (category, "*")
    if wildcard_key in FINDING_TECHNIQUE_MAP:
        return MappingResult(
            category=category,
            finding_name=finding_name,
            techniques=FINDING_TECHNIQUE_MAP[wildcard_key],
            match_type="category",
        )

    return MappingResult(
        category=category,
        finding_name=finding_name,
        techniques=[],
        match_type="none",
    )


def get_all_mappings() -> list[dict]:
    results = []
    for (category, pattern), techniques in FINDING_TECHNIQUE_MAP.items():
        results.append({
            "category": category,
            "finding_name_pattern": pattern,
            "techniques": techniques,
        })
    return sorted(results, key=lambda r: (r["category"], r["finding_name_pattern"]))
