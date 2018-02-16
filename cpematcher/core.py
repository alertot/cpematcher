import fnmatch

OR_OPERATOR = 'OR'
AND_OPERATOR = 'AND'


class CPE:
    cpe23_start = 'cpe:2.3:'
    fields = [
        'part', 'vendor', 'product', 'version', 'update', 'edition',
        'language', 'sw_edition', 'target_sw', 'target_hw', 'other',
    ]

    def __init__(self, cpe_str, vulnerable=True):
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


    def matches(self, another_cpe):
        for f in self.fields:
            value = getattr(self, f)
            another_value = getattr(another_cpe, f)

            if not fnmatch.fnmatch(another_value, value):
                return False

        return True


class CPEOperation:
    def __init__(self, operation_dict):
        self.cpes = set()

        operator = operation_dict['operator']

        if operator == OR_OPERATOR:
            for cpe_dict in operation_dict['cpe']:
                c = CPE(cpe_dict['cpe23Uri'], cpe_dict['vulnerable'])
                self.cpes.add(c)

    def matches(self, another_cpe):
        ''' Return matching CPE object. '''
        for cpe in self.cpes:
            if cpe.matches(another_cpe):
                return cpe

        return None
