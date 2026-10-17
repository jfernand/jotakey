"""Edit a .kicad_pcb file as text, for what the KiCad 10 pcbnew bindings cannot do safely:
removing items through them corrupts the remaining objects or crashes Python."""


def strip_blocks(text, drop):
    """Remove the top-level blocks of a .kicad_pcb file's text for which drop(block) is true.

    A block is a parenthesised expression directly inside (kicad_pcb ...), such as
    (segment ...) or (gr_line ...). Quoted strings may contain parentheses (net names like
    "Net-(D1-A)"), so the scan skips them.
    """
    out, i, depth = [], 0, 0
    while i < len(text):
        c = text[i]
        if depth == 1 and c == "(":
            j = block_end(text, i)
            block = text[i:j + 1]
            if drop(block):
                i = j + 1
                while i < len(text) and text[i] in " \t\n":
                    i += 1
                out.append("\t")
            else:
                out.append(block)
                i = j + 1
            continue
        out.append(c)
        if c == '"':
            j = string_end(text, i)
            out.append(text[i + 1:j + 1])
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        i += 1
    return "".join(out)


def block_end(text, i):
    """Index of the parenthesis closing the one at text[i]."""
    depth = 0
    while True:
        c = text[i]
        if c == '"':
            i = string_end(text, i)
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1


def string_end(text, i):
    """Index of the quote closing the string opened at text[i]."""
    j = i + 1
    while text[j] != '"':
        j += 2 if text[j] == "\\" else 1
    return j
