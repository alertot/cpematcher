import fnmatch

from .version import Version

OR_OPERATOR = 'OR'
AND_OPERATOR = 'AND'


class CPE:
    cpe23_start = 'cpe:2.3:'
    fields = [
        'part', 'vendor', 'product', 'version', 'update', 'edition',
        'language', 'sw_edition', 'target_sw', 'target_hw', 'other',
    ]

    def __init__(
            self,
            cpe_str,
            vulnerable=True,
            version_start_including=None,
            version_start_excluding=None,
            version_end_including=None,
            version_end_excluding=None,
        ):
        ''' Create CPE object with information about affected software.

        Usually CPE is used to find out if a version is vulnerable,
        but it's also used to test if a version is not vulnerable,
        then we added the argument `vulnerable`.

        There are some examples in CVE database.

        '''
        assert cpe_str.startswith(self.cpe23_start), "Only CPE 2.3 is supported"
        cpe_str = cpe_str.replace(self.cpe23_start, '')

        values = cpe_str.split(':')
        if len(values) != 11:
            raise ValueError('Incomplete number of fields')

        for f in self.fields:
            setattr(self, f, values.pop(0))

        self.is_vulnerable = vulnerable
        self.version_start_including = Version(version_start_including)
        self.version_start_excluding = Version(version_start_excluding)
        self.version_end_including = Version(version_end_including)
        self.version_end_excluding = Version(version_end_excluding)

    def matches(self, another_cpe):
        """ Verify if `another_cpe` matches, first through field comparison and
        then using the border constraints.

        """
        for f in self.fields:
            value = getattr(self, f)
            another_value = getattr(another_cpe, f)

            if not fnmatch.fnmatch(another_value, value):
                return False

        version = Version(another_cpe.version)

        # Do verifications on start version
        if self.version_start_including and version < self.version_start_including:
            return False

        if self.version_start_excluding and version <= self.version_start_excluding:
            return False

        if self.version_end_including and version > self.version_end_including:
            return False

        if self.version_end_excluding and version >= self.version_end_excluding:
            return False

        return True


class CPEOperation:
    ''' Handle operations defined on CPE sets.

    Support for:
        - OR operations

    '''
    VERSION_MAP = {
        'vsi': [
            'versionStartIncluding',
            'version_start_including',
        ],
        'vse': [
            'versionStartExcluding',
            'version_start_excluding',
        ],
        'vei': [
            'versioEndIncluding',
            'version_end_including',
        ],
        'vee': [
            'versioEndExcluding',
            'version_end_excluding',
        ],
    }

    def _get_value(self, cpe_dict, key):
        for k in self.VERSION_MAP[key]:
            if k in cpe_dict.keys():
                return cpe_dict[k]

        return None

    def __init__(self, operation_dict):
        self.cpes = set()

        operator = operation_dict['operator']

        if operator == OR_OPERATOR:
            for cpe_dict in operation_dict['cpe']:
                c = CPE(
                    cpe_dict['cpe23Uri'],
                    cpe_dict['vulnerable'],
                    version_start_including=self._get_value(cpe_dict, 'vsi'),
                    version_start_excluding=self._get_value(cpe_dict, 'vse'),
                    version_end_including=self._get_value(cpe_dict, 'vei'),
                    version_end_excluding=self._get_value(cpe_dict, 'vee'),
                )

                self.cpes.add(c)

    def matches(self, another_cpe):
        ''' Return matching CPE object. '''
        for cpe in self.cpes:
            if cpe.matches(another_cpe):
                return cpe

        return None
