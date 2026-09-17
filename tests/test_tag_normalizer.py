from attck_pipeline.sources.tag_normalizer import TagNormalizer


class TestTagNormalizer:
    def setup_method(self):
        self.normalizer = TagNormalizer()

    def test_valid_technique_id(self):
        result = self.normalizer.normalize("T1059")
        assert result.type == "technique_id"
        assert result.value == "T1059"

    def test_valid_subtechnique_id(self):
        result = self.normalizer.normalize("T1059.001")
        assert result.type == "technique_id"
        assert result.value == "T1059.001"

    def test_valid_tactic_id(self):
        result = self.normalizer.normalize("TA0001")
        assert result.type == "tactic_id"
        assert result.value == "TA0001"

    def test_valid_group_id(self):
        result = self.normalizer.normalize("G0007")
        assert result.type == "group_id"
        assert result.value == "G0007"

    def test_valid_software_id(self):
        result = self.normalizer.normalize("S0154")
        assert result.type == "software_id"
        assert result.value == "S0154"

    def test_tactic_shortname(self):
        result = self.normalizer.normalize("execution")
        assert result.type == "tactic_shortname"
        assert result.value == "execution"

    def test_domain(self):
        result = self.normalizer.normalize("Enterprise")
        assert result.type == "domain"
        assert result.value == "Enterprise"

    def test_plan_kind(self):
        result = self.normalizer.normalize("Emulation Plan")
        assert result.type == "plan_kind"
        assert result.value == "Emulation Plan"

    def test_free_label(self):
        result = self.normalizer.normalize("APT28")
        assert result.type == "free_label"
        assert result.value == "APT28"

    def test_quarantine_t1592_01(self):
        result = self.normalizer.normalize("T1592.01")
        assert result.type == "quarantine"
        assert result.suggested_fix == "T1592.001"

    def test_quarantine_ta001(self):
        result = self.normalizer.normalize("TA001")
        assert result.type == "quarantine"
        assert result.suggested_fix == "TA0001"

    def test_quarantine_t206(self):
        result = self.normalizer.normalize("T206")
        assert result.type == "quarantine"
        assert result.suggested_fix is None

    def test_quarantine_t1098_00(self):
        result = self.normalizer.normalize("T1098.00")
        assert result.type == "quarantine"
        assert result.suggested_fix == "T1098"

    def test_quarantine_t1592_02(self):
        result = self.normalizer.normalize("T1592.02")
        assert result.type == "quarantine"
        assert result.suggested_fix == "T1592.002"

    def test_quarantine_t1592_04(self):
        result = self.normalizer.normalize("T1592.04")
        assert result.type == "quarantine"
        assert result.suggested_fix == "T1592.004"

    def test_whitespace_trimmed(self):
        result = self.normalizer.normalize("  T1059  ")
        assert result.type == "technique_id"
        assert result.value == "T1059"

    def test_ransomware_free_label(self):
        result = self.normalizer.normalize("Ransomware")
        assert result.type == "free_label"

    def test_russia_free_label(self):
        result = self.normalizer.normalize("Russia")
        assert result.type == "free_label"
