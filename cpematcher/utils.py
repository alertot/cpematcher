# heavily inspired by https://stackoverflow.com/a/21882672
def split_cpe_string(string):
    ret = []
    current = []
    itr = iter(string)
    for ch in itr:
        if ch == "\\":
            try:
                # skip the next character; it has been escaped!
                current.append(next(itr))
            except StopIteration:
                pass
        elif ch == ":":
            # split! (add current to the list and reset it)
            ret.append("".join(current))
            current = []
        else:
            current.append(ch)

    ret.append("".join(current))
    return ret
