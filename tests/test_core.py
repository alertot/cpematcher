import pytest

from cpematcher.core import CPE, CPEOperation


class TestCPE:
    def test_init(self):
        c = CPE('cpe:2.3:a:apache:activemq:4.0.1:*:*:*:*:*:*:*')
        assert c.vendor == 'apache'

    def test_init_with_invalid_cpe_str(self):
        with pytest.raises(AssertionError):
            CPE('anystring')

    def test_init_with_invalid_number_of_values_in_cpe_str(self):
        with pytest.raises(ValueError):
            CPE('cpe:2.3:a:apache:activemq:4.0.1:*:*:*:*:*')

    def test_matches_with_wildcard(self):
        master_cpe = CPE('cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*')
        version_cpe = CPE('cpe:2.3:a:apache:activemq:4.0.1:*:*:*:*:*:*:*')

        assert master_cpe.matches(version_cpe)

    def test_matches_with_different_branch(self):
        branch_cpe = CPE('cpe:2.3:a:apache:activemq:4.1.*:*:*:*:*:*:*:*')
        version_cpe = CPE('cpe:2.3:a:apache:activemq:4.0.1:*:*:*:*:*:*:*')

        assert not branch_cpe.matches(version_cpe)

    def test_matches_with_same_branch(self):
        branch_cpe = CPE('cpe:2.3:a:apache:activemq:4.1.*:*:*:*:*:*:*:*')
        version_branch_cpe = CPE('cpe:2.3:a:apache:activemq:4.1.1:*:*:*:*:*:*:*')

        assert branch_cpe.matches(version_branch_cpe)

    def test_matches_with_exact_version(self):
        version_cpe = CPE('cpe:2.3:a:apache:activemq:4.1.1:*:*:*:*:*:*:*')

        assert version_cpe.matches(version_cpe)


class TestCPEOperation:
    def test_cpe_operation_with_or_operation(self):
        operation = {
            'operator': 'OR',
            'cpe': [
                {
                    'cpe23Uri': 'cpe:2.3:a:apache:activemq:4.1.*:*:*:*:*:*:*:*',
                    'vulnerable': True,
                },
                {
                    'cpe23Uri': 'cpe:2.3:a:apache:activemq:4.2.*:*:*:*:*:*:*:*',
                    'vulnerable': False,
                }
            ]
        }

        cpeo = CPEOperation(operation)
        version_cpe = CPE('cpe:2.3:a:apache:activemq:4.1.1:*:*:*:*:*:*:*')

        matching_cpe = cpeo.matches(version_cpe)
        assert matching_cpe.is_vulnerable
