from natsort import natsorted


class Version:
    def __init__(self, version):
        self.version = version

    def __bool__(self):
        return bool(self.version)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        return self.version == other.version

    def __ne__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        return self.version != other.version

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        if self.version == other.version:
            return False

        ns = natsorted([self.version, other.version])
        return ns[0] == self.version

    def __gt__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError

        if self.version == other.version:
            return False

        ns = natsorted([self.version, other.version])
        return ns[1] == self.version

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
