import contextlib


# heavily inspired by https://stackoverflow.com/a/21882672
def split_cpe_string(string: str) -> list[str]:
    ret = []
    current = []
    itr = iter(string)
    for ch in itr:
        if ch == "\\":
            with contextlib.suppress(StopIteration):
                # skip the next character; it has been escaped!
                current.append(next(itr))
        elif ch == ":":
            # split! (add current to the list and reset it)
            ret.append("".join(current))
            current = []
        else:
            current.append(ch)

    ret.append("".join(current))
    return ret
