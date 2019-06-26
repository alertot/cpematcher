from cpematcher.version import Version


class TestVersion:
    def test_bool(self):
        assert Version('1.1')
        assert not Version(None)

    def test_equal(self):
        assert Version('1.1.1') == Version('1.1.1')
        assert Version('1.1.1') != Version('1.1.2')

    def test_equal_reduntant_patch_level(self):
        assert Version('1.1') == Version("1.1.0")
        assert Version('1') == Version('1.0.0')
        assert Version('1.0') == Version('1.0')
        assert Version('1.0') != Version('1.0.1')

    def test_inequal(self):
        assert Version('1.1.1') != Version('1.1.2')
        assert Version('1.1.1') == Version('1.1.1')

    def test_lesser_than(self):
        assert Version('1.1.1') < Version('1.1.2')
        assert Version('1.7.3') < Version('1.12.2')
        assert Version('1.1.1') >= Version('1.1.0')

    def test_greater_than(self):
        assert Version('1.1.3') > Version('1.1.2')
        assert Version('1.12.3') > Version('1.7.2')
        assert Version('1.1.1') <= Version('1.1.2')

    def test_lesser_or_equal(self):
        assert Version('1.1.1') <= Version('1.1.2')
        assert Version('1.1.1') <= Version('1.1.1')

    def test_greater_or_equal(self):
        assert Version('1.1.5') >= Version('1.1.2')
        assert Version('1.1.1') >= Version('1.1.1')
