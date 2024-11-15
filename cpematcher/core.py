import fnmatch
from typing import Self

from .utils import split_cpe_string
from .version import Version

CPEv23 = "cpe:2.3:"


class CPE:
    def __init__(
        self,
        cpe_str: str,
        vulnerable: bool = True,
        version_start_including: str | None = None,
        version_start_excluding: str | None = None,
        version_end_including: str | None = None,
        version_end_excluding: str | None = None,
    ):
        """Create CPE object with information about affected software.

        Usually CPE is used to find out if a version is vulnerable,
        but it's also used to test if a version is not vulnerable,
        then we added the argument `vulnerable`.

        There are some examples in CVE database.
        """
        assert cpe_str.startswith(CPEv23), "Only CPE 2.3 is supported"

        attr_values = split_cpe_string(cpe_str)
        if len(attr_values) != 13:
            raise ValueError("Incomplete number of CPE attributes")

        (
            *_,
            self.part,
            self.vendor,
            self.product,
            self.version_str,
            self.update,
            self.edition,
            self.language,
            self.sw_edition,
            self.target_sw,
            self.target_hw,
            self.other,
        ) = attr_values

        self.is_vulnerable = vulnerable

        self.version = Version(self.version_str)
        self.version_start_including = Version(version_start_including)
        self.version_start_excluding = Version(version_start_excluding)
        self.version_end_including = Version(version_end_including)
        self.version_end_excluding = Version(version_end_excluding)

    @property
    def no_version(self) -> tuple[str, str, str, str, str, str, str, str, str, str]:
        return (
            self.part,
            self.vendor,
            self.product,
            self.update,
            self.edition,
            self.language,
            self.sw_edition,
            self.target_sw,
            self.target_hw,
            self.other,
        )

    def matches(self, other: Self) -> bool:
        """Verify if `other` matches, first through attribute comparison
        then using version matching and border constraints.
        """
        return self._matches_fields(other) and self._matches_version(other)

    @staticmethod
    def _glob_equal(value1: str, value2: str) -> bool:
        value1, value2 = value1.lower(), value2.lower()
        # Depending on the order, fnmatch.fnmatch could return False if wildcard
        # is the first value. As wildcard should always return True in any case,
        # we reorder the arguments based on that.
        glob_values = [value1, value2] if value2 == "*" else [value2, value1]
        return fnmatch.fnmatch(*glob_values)

    def _matches_fields(self, other: Self) -> bool:
        return all(
            self._glob_equal(value, other_value)
            for value, other_value in zip(self.no_version, other.no_version)
        )

    def _matches_version(self, other: Self) -> bool:  # noqa: C901
        if "*" in self.version_str or "*" in other.version_str:
            if not self._glob_equal(self.version_str, other.version_str):
                return False
        elif self.version != other.version:
            return False

        if (
            self.version_start_including
            and other.version < self.version_start_including
        ):
            return False
        if (
            self.version_start_excluding
            and other.version <= self.version_start_excluding
        ):
            return False
        if self.version_end_including and other.version > self.version_end_including:
            return False
        if self.version_end_excluding and other.version >= self.version_end_excluding:
            return False

        # ruff: noqa: SIM103
        return True


class CPEOperation:
    """Handle operations defined on CPE sets.
    Support only OR operations.
    """

    VERSION_MAP = {
        "vsi": ["versionStartIncluding", "version_start_including"],
        "vse": ["versionStartExcluding", "version_start_excluding"],
        "vei": ["versionEndIncluding", "version_end_including"],
        "vee": ["versionEndExcluding", "version_end_excluding"],
    }

    def _get_value(self, cpe_dict, key):
        for k in self.VERSION_MAP[key]:
            if k in cpe_dict:
                return cpe_dict[k]

        return None

    def __init__(self, operation_dict):
        self.cpes = set()

        if operation_dict["operator"] != "OR":
            return None

        for cpe_dict in operation_dict["cpe"]:
            cpe = CPE(
                cpe_dict["cpe23Uri"],
                cpe_dict.get("vulnerable"),
                version_start_including=self._get_value(cpe_dict, "vsi"),
                version_start_excluding=self._get_value(cpe_dict, "vse"),
                version_end_including=self._get_value(cpe_dict, "vei"),
                version_end_excluding=self._get_value(cpe_dict, "vee"),
            )

            self.cpes.add(cpe)

    def matches(self, other: CPE) -> CPE | None:
        """Return matching CPE object."""
        return next((cpe for cpe in self.cpes if cpe.matches(other)), None)
