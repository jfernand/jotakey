# (c) Javier Fernandez @ JotaSoft 2026
"""Copy KiCad standard-library symbols into the project library (lib/jotakey.kicad_sym).

The project keeps its own copy of every symbol it uses, so it opens identically on any machine
and does not depend on which KiCad version's libraries are installed. Run from this directory:

    python3 import_symbols.py /usr/share/kicad/symbols

A symbol that `extends` another is copied together with its parent. Symbols already present in
the project library are left alone.
"""
import pathlib
import re
import sys

WANTED = {
    "Device": ["R", "C", "LED"],
    "Connector": ["TestPoint"],
    "Regulator_Linear": ["XC6206PxxxMR"],
    "Power_Protection": ["USBLC6-2SC6"],
    "MCU_ST_STM32L4": ["STM32L432KCUx"],
    "power": ["GND", "+3V3", "VBUS", "PWR_FLAG"],
}


def top_level_symbols(text: str) -> dict[str, str]:
    """Map name -> source text of each top-level (symbol "...") block."""
    out = {}
    for m in re.finditer(r'\n\t\(symbol "([^"]+)"', text):
        start = m.start() + 1
        depth = 0
        i = start
        in_str = False
        while True:
            c = text[i]
            if in_str:
                if c == "\\":
                    i += 1
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out[m.group(1)] = text[start : i + 1]
    return out


def main() -> None:
    src_dir = pathlib.Path(sys.argv[1])
    lib = pathlib.Path(__file__).with_name("jotakey.kicad_sym")
    lib_text = lib.read_text()
    present = set(re.findall(r'^\s*\(symbol "([^"]+)"', lib_text, re.M))
    blocks = []
    for library, names in WANTED.items():
        symbols = top_level_symbols((src_dir / f"{library}.kicad_sym").read_text())
        queue = list(names)
        while queue:
            name = queue.pop(0)
            if name in present:
                continue
            block = symbols[name]
            parent = re.search(r'\(extends "([^"]+)"\)', block)
            if parent:
                queue.append(parent.group(1))
            blocks.append(block)
            present.add(name)
            print(f"imported {library}:{name}")
    end = lib_text.rstrip().rfind(")")
    lib.write_text(lib_text[:end] + "".join("\t" + b + "\n" for b in blocks) + ")\n")


main()
