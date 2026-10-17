# (c) Javier Fernandez @ JotaSoft 2026
"""Build the JLCPCB order package for the jotakey-key board.

    KICAD_CLI="~/Applications/kicad-10.0.7-x86_64.AppImage kicad-cli" python3 tools/fab.py

KICAD_CLI is the command that runs KiCad 10's kicad-cli (default: "kicad-cli"). The package
goes to fab/hw-v<HW_VERSION>/ (not tracked by git; rebuild it from the tagged sources):

    jotakey-key-hw-v<version>-gerbers.zip   copper, mask, paste, silkscreen, outline + drill
    jotakey-key-hw-v<version>-bom.csv       JLCPCB BOM: Comment, Designator, Footprint, LCSC Part #
    jotakey-key-hw-v<version>-cpl.csv       JLCPCB pick and place: Designator, Mid X, Mid Y, Layer, Rotation
    erc.rpt, drc.rpt                        the checks the package was built after

The build stops unless the schematic passes ERC and the board passes DRC with schematic parity.
Only parts with an LCSC number are assembled; the edge connector, the touch electrode and
the test pads are copper on the board and appear in neither the BOM nor the placement file.

Rotations are KiCad's. Check every part's orientation in JLCPCB's placement preview before
paying (hardware/MANUFACTURING.md lists what to look for); record a needed correction in
ROTATION_OFFSETS so the next build carries it.
"""
import csv
import io
import json
import os
import pathlib
import shlex
import subprocess
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent.parent
NAME = "jotakey-key"
GERBER_LAYERS = ["F.Cu", "B.Cu", "F.Paste", "B.Paste", "F.Silkscreen", "B.Silkscreen",
                 "F.Mask", "B.Mask", "Edge.Cuts"]
# Reference -> degrees added to KiCad's rotation for JLCPCB, where its preview shows a part
# turned. Empty until a preview shows otherwise.
ROTATION_OFFSETS = {}


def kicad(*args):
    cmd = shlex.split(os.path.expanduser(os.environ.get("KICAD_CLI", "kicad-cli")))
    subprocess.run(cmd + list(args), check=True, cwd=HERE)


def version():
    pro = json.loads((HERE / f"{NAME}.kicad_pro").read_text())
    return pro["text_variables"]["HW_VERSION"]


def checks(out):
    kicad("sch", "erc", "--exit-code-violations", "-o", str(out / "erc.rpt"), f"{NAME}.kicad_sch")
    kicad("pcb", "drc", "--exit-code-violations", "--schematic-parity", "--refill-zones",
          "-o", str(out / "drc.rpt"), f"{NAME}.kicad_pcb")


def gerbers(out, stem):
    with tempfile.TemporaryDirectory() as tmp:
        kicad("pcb", "export", "gerbers", "--check-zones", "--layers", ",".join(GERBER_LAYERS),
              "-o", tmp + "/", f"{NAME}.kicad_pcb")
        kicad("pcb", "export", "drill", "--format", "excellon", "--excellon-units", "mm",
              "-o", tmp + "/", f"{NAME}.kicad_pcb")
        files = sorted(pathlib.Path(tmp).iterdir())
        with zipfile.ZipFile(out / f"{stem}-gerbers.zip", "w", zipfile.ZIP_DEFLATED) as z:
            for f in files:
                z.write(f, f.name)
        return [f.name for f in files]


def bom(out, stem):
    """Write the JLCPCB BOM; return {reference: LCSC part} for the assembled parts."""
    with tempfile.TemporaryDirectory() as tmp:
        raw = pathlib.Path(tmp, "bom.csv")
        kicad("sch", "export", "bom", "--fields", "Value,Reference,Footprint,LCSC",
              "--labels", "Comment,Designator,Footprint,LCSC Part #",
              "--group-by", "Value,Footprint,LCSC", "--ref-range-delimiter", "",
              "-o", str(raw), f"{NAME}.kicad_sch")
        rows = list(csv.DictReader(io.StringIO(raw.read_text())))
    rows = [r for r in rows if r["LCSC Part #"].strip()]
    for r in rows:
        r["Footprint"] = r["Footprint"].split(":")[-1]
    with open(out / f"{stem}-bom.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Comment", "Designator", "Footprint", "LCSC Part #"])
        w.writeheader()
        w.writerows(rows)
    return {ref.strip(): r["LCSC Part #"] for r in rows for ref in r["Designator"].split(",")}


def cpl(out, stem, parts):
    with tempfile.TemporaryDirectory() as tmp:
        raw = pathlib.Path(tmp, "pos.csv")
        kicad("pcb", "export", "pos", "--format", "csv", "--units", "mm", "--side", "both",
              "--exclude-dnp", "-o", str(raw), f"{NAME}.kicad_pcb")
        rows = list(csv.DictReader(io.StringIO(raw.read_text())))
    placed = []
    for r in rows:
        ref = r["Ref"]
        if ref not in parts:
            continue
        rot = (float(r["Rot"]) + ROTATION_OFFSETS.get(ref, 0)) % 360
        placed.append({"Designator": ref, "Mid X": f'{float(r["PosX"]):.4f}mm',
                       "Mid Y": f'{float(r["PosY"]):.4f}mm',
                       "Layer": "Top" if r["Side"] == "top" else "Bottom",
                       "Rotation": f"{rot:g}"})
    missing = sorted(set(parts) - {p["Designator"] for p in placed})
    if missing:
        raise SystemExit(f"parts in the BOM but not on the board: {missing}")
    with open(out / f"{stem}-cpl.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Designator", "Mid X", "Mid Y", "Layer", "Rotation"])
        w.writeheader()
        w.writerows(placed)
    return placed


def main():
    ver = version()
    stem = f"{NAME}-hw-v{ver}"
    out = HERE / "fab" / f"hw-v{ver}"
    out.mkdir(parents=True, exist_ok=True)
    checks(out)
    files = gerbers(out, stem)
    parts = bom(out, stem)
    placed = cpl(out, stem, parts)
    print(f"hardware {ver}: {len(files)} fabrication files, {len(placed)} placed parts "
          f"({len(set(parts.values()))} BOM lines) -> {out.relative_to(HERE)}")


main()
