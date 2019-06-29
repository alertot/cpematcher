from natsort import natsorted


class Version:
    def __init__(self, version):
        self.version = version

    def __bool__(self):
        return bool(self.version)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        return self.version == other.version or self.__eq_ignore_trailing_zeros(other)

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        return not self.__eq__(other)

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        if self.__eq__(other):
            return False

        ns = natsorted([self.version, other.version])
        return self.__eq__(Version(ns[0]))

    def __gt__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        if self.__eq__(other):
            return False

        ns = natsorted([self.version, other.version])
        return self.__eq__(Version(ns[1]))

    def __le__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        eq = self.__eq__(other)
        return eq or self.__lt__(other)

    def __ge__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        eq = self.__eq__(other)
        return eq or self.__gt__(other)

    def __eq_ignore_trailing_zeros(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        self_trimmed = self.version
        while self_trimmed.endswith(".0"):
            self_trimmed = self_trimmed[:-2]

        other_trimmed = other.version
        while other_trimmed.endswith(".0"):
            other_trimmed = other_trimmed[:-2]

        return self_trimmed == other_trimmed
