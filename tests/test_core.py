import pytest

from cpematcher.core import CPE, CPEOperation


class TestCPE:
    template = "cpe:2.3:a:apache:activemq:%s:*:*:*:*:*:*:*"

    def test_init(self):
        cpe_basic = CPE("cpe:2.3:a:apache:activemq:4.0.1:*:*:*:*:*:*:*")
        assert cpe_basic.vendor == "apache"

        # CVE-2018-12015, NIST NVD data feed (json)
        cpe_escaped = CPE(
            "cpe:2.3:a:archive\\:\\:tar_project:archive\\:\\:tar:*:*:*:*:*:perl:*:*"
        )
        assert cpe_escaped.vendor == "archive::tar_project"

    def test_init_with_invalid_cpe_str(self):
        with pytest.raises(AssertionError):
            CPE("anystring")

    def test_init_with_invalid_number_of_values_in_cpe_str(self):
        with pytest.raises(ValueError):
            CPE("cpe:2.3:a:apache:activemq:4.0.1:*:*:*:*:*")

    def test_matches_with_wildcard(self):
        master_cpe = CPE("cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*")
        version_cpe = CPE("cpe:2.3:a:apache:activemq:4.0.1:*:*:*:*:*:*:*")

        assert master_cpe.matches(version_cpe)

    def test_matches_with_wildcard_inverse(self):
        version_cpe = CPE("cpe:2.3:a:apache:activemq:4.0.1:*:*:*:*:*:*:*")
        master_cpe = CPE("cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*")

        assert version_cpe.matches(master_cpe)

    def test_matches_with_different_branch(self):
        branch_cpe = CPE("cpe:2.3:a:apache:activemq:4.1.*:*:*:*:*:*:*:*")
        version_cpe = CPE("cpe:2.3:a:apache:activemq:4.0.1:*:*:*:*:*:*:*")

        assert not branch_cpe.matches(version_cpe)

    def test_matches_with_same_branch(self):
        branch_cpe = CPE("cpe:2.3:a:apache:activemq:4.1.*:*:*:*:*:*:*:*")
        version_branch_cpe = CPE("cpe:2.3:a:apache:activemq:4.1.1:*:*:*:*:*:*:*")

        assert branch_cpe.matches(version_branch_cpe)

    def test_matches_with_exact_version(self):
        version_cpe = CPE("cpe:2.3:a:apache:activemq:4.1.1:*:*:*:*:*:*:*")
        assert version_cpe.matches(version_cpe)

    def test_matches_case_insensitive(self):
        cpe_str = "cpe:2.3:a:apache:activemq:4.1.1:*:*:*:*:*:*:*"
        cpe = CPE(cpe_str)
        upper_cpe = CPE(cpe_str.replace("apche", "APACHE"))
        assert cpe.matches(upper_cpe)

        cpe_alnum_version = (
            "cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*"
        )
        alnum_cpe = CPE(cpe_alnum_version)
        cpe_alnum_upper = CPE(cpe_alnum_version.replace("r2:sp1", "R2:SP1"))
        assert alnum_cpe.matches(cpe_alnum_upper)

    def test_matches_with_version_start_including(self):
        branch_cpe = CPE(self.template % "4.1.*", version_start_including="4.1.3")

        assert not branch_cpe.matches(CPE(self.template % "4.1.2"))
        assert branch_cpe.matches(CPE(self.template % "4.1.3"))
        assert branch_cpe.matches(CPE(self.template % "4.1.4"))

    def test_matches_with_version_start_excluding(self):
        branch_cpe = CPE(self.template % "4.1.*", version_start_excluding="4.1.3")

        assert not branch_cpe.matches(CPE(self.template % "4.1.2"))
        assert not branch_cpe.matches(CPE(self.template % "4.1.3"))
        assert branch_cpe.matches(CPE(self.template % "4.1.4"))

    def test_matches_with_version_end_including(self):
        branch_cpe = CPE(self.template % "4.1.*", version_end_including="4.1.3")

        assert branch_cpe.matches(CPE(self.template % "4.1.2"))
        assert branch_cpe.matches(CPE(self.template % "4.1.3"))
        assert not branch_cpe.matches(CPE(self.template % "4.1.4"))

    def test_matches_with_version_end_excluding(self):
        branch_cpe = CPE(self.template % "4.1.*", version_end_excluding="4.1.3")

        assert branch_cpe.matches(CPE(self.template % "4.1.2"))
        assert not branch_cpe.matches(CPE(self.template % "4.1.3"))
        assert not branch_cpe.matches(CPE(self.template % "4.1.4"))

    def test_matches_with_reduntant_patch_level(self):
        first = CPE(self.template % "4.2")
        second = CPE(self.template % "4.2.0")

        assert first.matches(second)
        assert second.matches(first)


class TestCPEOperation:
    def test_cpe_operation_with_or_operation(self):
        operation = {
            "operator": "OR",
            "cpe": [
                {
                    "cpe23Uri": "cpe:2.3:a:apache:activemq:4.1.*:*:*:*:*:*:*:*",
                    "vulnerable": True,
                },
                {
                    "cpe23Uri": "cpe:2.3:a:apache:activemq:4.2.*:*:*:*:*:*:*:*",
                    "vulnerable": False,
                },
            ],
        }

        cpeo = CPEOperation(operation)
        version_cpe = CPE("cpe:2.3:a:apache:activemq:4.1.1:*:*:*:*:*:*:*")

        matching_cpe = cpeo.matches(version_cpe)
        assert matching_cpe.is_vulnerable
