# (c) Javier Fernandez @ JotaSoft 2026
"""Render the jotakey-key board, front and back, for the document (docs/figures/).

    KICAD_CLI="~/Applications/kicad-10.0.7-x86_64.AppImage kicad-cli" python3 tools/render.py

Uses the board stackup's colours (black mask, white silkscreen) and a transparent
background, then trims the empty margin (needs ImageMagick's `convert`).
"""
import os
import pathlib
import shlex
import subprocess

HERE = pathlib.Path(__file__).resolve().parent.parent
FIGURES = HERE.parent.parent / "docs" / "figures"


def main():
    FIGURES.mkdir(exist_ok=True)
    cli = shlex.split(os.path.expanduser(os.environ.get("KICAD_CLI", "kicad-cli")))
    for side, name in (("top", "front"), ("bottom", "back")):
        out = FIGURES / f"jotakey-key-{name}.png"
        subprocess.run(cli + ["pcb", "render", "--side", side, "--quality", "high",
                              "--use-board-stackup-colors", "--background", "transparent",
                              "--width", "1200", "--height", "2000", "-o", str(out),
                              "jotakey-key.kicad_pcb"],
                       check=True, cwd=HERE, stdout=subprocess.DEVNULL)
        subprocess.run(["convert", str(out), "-trim", "+repage", str(out)], check=True)
        print(out.relative_to(HERE.parent.parent))


main()
