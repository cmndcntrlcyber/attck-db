from attck_pipeline.sources.nemesis_mapping import get_all_mappings, resolve_techniques


class TestNemesisMapping:
    def test_exact_match_chromium_logins(self):
        result = resolve_techniques("CREDENTIAL", "chromium_logins")
        assert result.match_type == "exact"
        assert "T1555.003" in result.techniques

    def test_exact_match_parsed_credentials(self):
        result = resolve_techniques("CREDENTIAL", "parsed_credentials")
        assert result.match_type == "exact"
        assert "T1003" in result.techniques

    def test_exact_match_chromium_cookies(self):
        result = resolve_techniques("CREDENTIAL", "chromium_cookies")
        assert result.match_type == "exact"
        assert "T1539" in result.techniques

    def test_exact_match_dpapi_masterkey(self):
        result = resolve_techniques("CREDENTIAL", "dpapi_masterkey")
        assert result.match_type == "exact"
        assert "T1555.004" in result.techniques

    def test_exact_match_git_credentials(self):
        result = resolve_techniques("CREDENTIAL", "git_credentials")
        assert result.match_type == "exact"
        assert "T1552.001" in result.techniques

    def test_exact_match_gpp_passwords(self):
        result = resolve_techniques("CREDENTIAL", "gpp_passwords")
        assert result.match_type == "exact"
        assert "T1552.006" in result.techniques

    def test_exact_match_ntlm_hash(self):
        result = resolve_techniques("EXTRACTED_HASH", "ntlm_hash")
        assert result.match_type == "exact"
        assert "T1003.001" in result.techniques

    def test_exact_match_keytab(self):
        result = resolve_techniques("EXTRACTED_DATA", "keytab")
        assert result.match_type == "exact"
        assert "T1558" in result.techniques

    def test_exact_match_lsass_dump(self):
        result = resolve_techniques("EXTRACTED_DATA", "lsass_dump")
        assert result.match_type == "exact"
        assert "T1003.001" in result.techniques

    def test_exact_match_ntds_dit(self):
        result = resolve_techniques("EXTRACTED_DATA", "ntds_dit")
        assert result.match_type == "exact"
        assert "T1003.003" in result.techniques

    def test_prefix_match_dpapi_unknown(self):
        result = resolve_techniques("CREDENTIAL", "dpapi_something_new")
        assert result.match_type == "prefix"
        assert "T1555.004" in result.techniques

    def test_prefix_match_chromium_unknown(self):
        result = resolve_techniques("CREDENTIAL", "chromium_new_feature")
        assert result.match_type == "prefix"
        assert "T1555.003" in result.techniques

    def test_category_fallback_credential(self):
        result = resolve_techniques("CREDENTIAL", "totally_unknown_type")
        assert result.match_type == "category"
        assert "T1552" in result.techniques

    def test_category_fallback_extracted_hash(self):
        result = resolve_techniques("EXTRACTED_HASH", "some_new_hash_type")
        assert result.match_type == "category"
        assert "T1003" in result.techniques

    def test_category_fallback_pii(self):
        result = resolve_techniques("PII", "ssn_detected")
        assert result.match_type == "category"
        assert "T1530" in result.techniques

    def test_unmapped_yara_match(self):
        result = resolve_techniques("YARA_MATCH", "custom_rule_123")
        assert result.match_type == "none"
        assert result.techniques == []

    def test_unmapped_informational(self):
        result = resolve_techniques("INFORMATIONAL", "file_metadata")
        assert result.match_type == "none"
        assert result.techniques == []

    def test_unmapped_unknown_category(self):
        result = resolve_techniques("TOTALLY_NEW", "something")
        assert result.match_type == "none"
        assert result.techniques == []

    def test_get_all_mappings_returns_list(self):
        mappings = get_all_mappings()
        assert isinstance(mappings, list)
        assert len(mappings) > 0
        assert all("category" in m and "techniques" in m for m in mappings)

    def test_get_all_mappings_sorted(self):
        mappings = get_all_mappings()
        categories = [m["category"] for m in mappings]
        assert categories == sorted(categories)
