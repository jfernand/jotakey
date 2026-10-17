"""Route the jotakey-key board: keep-outs, hand-routed critical nets, Freerouting for the rest,
then GND pours on both layers (hatched behind the touch electrode).

Works on the saved jotakey-key.kicad_pcb through KiCad's pcbnew bindings, because Specctra
DSN export and SES import exist only there. Run it with KiCad's own Python, after layout.py:

    FREEROUTING=/path/to/freerouting  <kicad>/AppRun python3.11 tools/route.py

where FREEROUTING runs Freerouting 2.5 (java -jar freerouting-2.5.0.jar; needs Java 25).

If the board is open in KiCad, save it first and revert it afterwards (File > Revert), so
KiCad picks up the routed file. Every run starts by deleting all tracks, vias and zones, so
the result depends only on the placement and on this file.

Coordinates are board millimetres, as in layout.py.
"""
import math
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

import pcbnew

from boardtext import strip_blocks

HERE = pathlib.Path(__file__).resolve().parent
BOARD = HERE.parent / "jotakey-key.kicad_pcb"

VIA = (0.6, 0.3)            # diameter, drill
ELECTRODE = (100.0, 108.0)  # touch electrode centre (E1, layout.py), copper radius 5 mm
# AN4312 3.5.6: keep ground and other copper >= 2 mm (4-5 mm recommended) from the electrode
# on its own layer. Top: 4 mm, so nothing but the electrode's own trace within 9 mm of its
# centre. Bottom: only the GND hatch below, out to 1 mm beyond the electrode.
ELECTRODE_GAP_TOP = 5.0 + 4.0
ELECTRODE_UNDER = 6.0
# AN4312 3.5.6: a 10 % copper mesh on the side opposite the electrode. Square hatch of lines t
# wide at pitch p covers 1 - ((p - t) / p)^2 of the area: 0.2 mm lines, 3.7 mm gaps -> 10 %.
ELECTRODE_HATCH = (0.2, 3.7)  # line width, gap
TONGUE = ((93.5, 69.5), (106.5, 82.0))  # USB-A plug tongue: contacts only on top, nothing below
POUR = ((90.0, 82.0), (110.0, 118.0))   # GND pour outline; the board edge clips it
EDGE_CLEARANCE = 0.5        # board setup; Freerouting does not read it, so keep-outs carry it
END_ARC = ((100.0, 108.0), 9.0)         # the rounded end: centre, radius (layout.py)

# Hand-routed connections, fixed before autorouting: (net, layer, width, points).
TRACKS = [
    # USB from the plug to U4. D- and D+ run straight down; U4's channels follow the plug order.
    ("/USB_CONN_DM", "F", 0.2, [(99.05, 78.5), (99.05, 83.86)]),
    ("/USB_CONN_DP", "F", 0.2, [(100.95, 78.5), (100.95, 83.86)]),
    # USB from U4 to the MCU, where D+ and D- swap sides: D- stays on top,
    # D+ hops under it on the bottom layer.
    ("/USB_DM", "F", 0.2, [(99.05, 86.14), (99.05, 88.0), (99.75, 88.7), (99.75, 91.06)]),
    ("/USB_DP", "F", 0.2, [(100.95, 86.14), (100.95, 87.5)]),
    ("/USB_DP", "B", 0.2, [(100.95, 87.5), (100.95, 88.1), (100.15, 88.9), (98.9, 88.9)]),
    ("/USB_DP", "F", 0.2, [(98.9, 88.9), (99.25, 89.25), (99.25, 91.06)]),
    # VBUS: plug -> LDO input and C1 on top; U4's VBUS pin through the bottom layer.
    ("VBUS", "F", 0.4, [(96.5, 78.5), (96.5, 82.6), (95.5, 83.6), (95.5, 84.68), (92.6, 84.68)]),
    ("VBUS", "B", 0.3, [(96.5, 82.6), (97.3, 83.4), (97.3, 84.8), (100.0, 87.5)]),
    ("VBUS", "F", 0.3, [(100.0, 86.14), (100.0, 87.5)]),
    # Under the MCU. NRST: pin 4 -> C8 -> a via between C4 and C8 -> TP3 on the bottom.
    ("/NRST", "F", 0.2, [(99.75, 95.94), (99.75, 97.22), (98.75, 97.22)]),
    ("/NRST", "B", 0.2, [(98.75, 97.22), (99.95, 98.42)]),
    # 3V3: VDD pin 1 -> C4, VDDA pin 5 -> C6 -> C7; a bottom-layer link under the MCU joins
    # them and feeds TP4.
    ("+3V3", "F", 0.2, [(98.25, 95.94), (98.25, 96.5), (97.8, 96.95), (97.8, 97.22), (96.9, 97.22)]),
    ("+3V3", "F", 0.2, [(100.25, 95.94), (100.25, 96.5), (100.85, 97.1), (100.85, 97.22),
                        (101.95, 97.22), (102.9, 97.22)]),
    ("+3V3", "B", 0.3, [(96.9, 97.22), (97.6, 96.52), (102.2, 96.52), (102.9, 97.22),
                        (102.54, 98.4)]),
    # MCU VDD pin 17: a via at the package corner lets SDA and SCL pass over it; C5 beside it.
    ("+3V3", "F", 0.2, [(101.75, 91.06), (101.75, 90.5), (102.0, 90.25), (102.55, 90.25),
                        (103.7, 90.42)]),
    # Bottom-layer link down the MCU's right side: pin 17's corner via to the 3V3 under it.
    ("+3V3", "B", 0.3, [(102.55, 90.25), (102.55, 96.87), (102.9, 97.22)]),
    # C5 -> R4's 3V3 end, under SCL.
    ("+3V3", "F", 0.2, [(103.7, 90.42), (104.05, 90.77), (104.65, 90.77), (105.0, 91.11)]),
    # The OPTIGA's VCC and C9 sit beyond SE_RST: a bottom-layer hop from the R4 side.
    ("+3V3", "F", 0.2, [(105.0, 91.11), (105.78, 90.7)]),
    ("+3V3", "B", 0.2, [(105.78, 90.7), (107.1, 89.7)]),
    ("+3V3", "F", 0.2, [(107.1, 89.7), (107.9, 89.22)]),
    # SE_RST leaves pin 11 straight, between pins 10 and 12, before Freerouting takes over.
    ("/SE_RST", "F", 0.2, [(102.44, 94.25), (103.4, 94.25)]),
    # BOOT0 pull-down, straight across.
    ("/BOOT0", "F", 0.2, [(96.31, 94.75), (97.56, 94.75)]),
    # Touch electrode: down the left side, away from the other signals, into the pad's edge.
    ("/TOUCH_ELECTRODE", "F", 0.2, [(95.29, 93.3), (94.5, 93.3), (94.5, 101.0), (97.6, 104.1)]),
]
VIAS = [
    ("/USB_DP", (100.95, 87.5)),
    ("/USB_DP", (98.9, 88.9)),
    ("VBUS", (96.5, 82.6)),
    ("VBUS", (100.0, 87.5)),
    ("/NRST", (98.75, 97.22)),
    ("+3V3", (96.9, 97.22)),
    ("+3V3", (102.9, 97.22)),
    ("+3V3", (102.55, 90.25)),
    ("+3V3", (105.78, 90.7)),
    ("+3V3", (107.1, 89.7)),
]
# GND is not autorouted: the pours carry it. These connect what the pours cannot reach.
GND_TRACKS = [
    ("F", 0.5, [(103.5, 78.5), (103.5, 83.0)]),   # plug GND contact into the top pour
    ("F", 0.3, [(100.0, 83.86), (100.0, 82.5)]),  # U4 GND, boxed in by D- and D+
    ("F", 0.2, [(97.56, 95.25), (97.1, 95.25), (96.6, 95.75)]),  # U1 pin 32, a corner pin
    # U1 pin 16 -> C5 and into U1's exposed pad, between pins 15 and 17.
    ("F", 0.2, [(103.7, 91.38), (102.44, 91.75)]),
    ("F", 0.2, [(102.44, 91.82), (101.6, 91.82)]),
    ("F", 0.2, [(106.9, 84.925), (106.9, 85.8)]),  # U2 pin 1 into its exposed pad
    ("F", 0.2, [(107.9, 90.18), (107.9, 91.0)]),   # C9 GND, hemmed in by the board edge
]
GND_VIAS = [
    (100.0, 82.5),
    (92.3, 86.7),   # the top pour around the LDO, between C1 and C3
    (96.6, 95.75),
    # U1's exposed pad (VSS) to the bottom pour.
    (99.3, 92.8), (100.7, 92.8), (99.3, 94.2), (100.7, 94.2),
    # U2's exposed pad.
    (105.3, 86.4), (106.5, 86.4),
    (107.9, 91.0),
]


def mm(x, y):
    return pcbnew.VECTOR2I(pcbnew.FromMM(x), pcbnew.FromMM(y))


def layer(name):
    return pcbnew.F_Cu if name == "F" else pcbnew.B_Cu


def add_track(board, net, side, width, points):
    for a, b in zip(points, points[1:]):
        t = pcbnew.PCB_TRACK(board)
        t.SetStart(mm(*a))
        t.SetEnd(mm(*b))
        t.SetWidth(pcbnew.FromMM(width))
        t.SetLayer(layer(side))
        t.SetNet(board.FindNet(net))
        t.SetLocked(True)
        board.Add(t)


def add_via(board, net, at):
    v = pcbnew.PCB_VIA(board)
    v.SetPosition(mm(*at))
    v.SetWidth(pcbnew.FromMM(VIA[0]))
    v.SetDrill(pcbnew.FromMM(VIA[1]))
    v.SetLayerPair(pcbnew.F_Cu, pcbnew.B_Cu)
    v.SetNet(board.FindNet(net))
    v.SetLocked(True)
    board.Add(v)


def outline(zone, points):
    poly = zone.Outline()
    poly.NewOutline()
    for p in points:
        poly.Append(pcbnew.FromMM(p[0]), pcbnew.FromMM(p[1]))


def rect(a, b):
    return [a, (b[0], a[1]), b, (a[0], b[1])]


def circle(centre, r, n=64):
    return [(centre[0] + r * math.cos(2 * math.pi * i / n),
             centre[1] + r * math.sin(2 * math.pi * i / n)) for i in range(n)]


def layers(*names):
    s = pcbnew.LSET()
    for n in names:
        s.AddLayer(layer(n))
    return s


def keepout(board, name, sides, points, tracks=False, vias=False, pours=False):
    z = pcbnew.ZONE(board)
    z.SetIsRuleArea(True)
    z.SetZoneName(name)
    z.SetLayerSet(layers(*sides))
    z.SetDoNotAllowTracks(tracks)
    z.SetDoNotAllowVias(vias)
    z.SetDoNotAllowZoneFills(pours)
    z.SetDoNotAllowPads(False)
    z.SetDoNotAllowFootprints(False)
    outline(z, points)
    board.Add(z)


def gnd_zone(board, side, name, points):
    z = pcbnew.ZONE(board)
    z.SetLayer(layer(side))
    z.SetNet(board.FindNet("GND"))
    z.SetZoneName(name)
    z.SetLocalClearance(pcbnew.FromMM(0.2))
    z.SetMinThickness(pcbnew.FromMM(0.2))
    z.SetThermalReliefGap(pcbnew.FromMM(0.25))
    outline(z, points)
    board.Add(z)
    return z


def gnd_pour(board, side, hole=None):
    z = gnd_zone(board, side, f"GND {side}", rect(*POUR))
    if hole:
        poly = z.Outline()
        poly.NewHole()
        for p in hole:
            poly.Append(pcbnew.FromMM(p[0]), pcbnew.FromMM(p[1]), 0, 0)


def gnd_hatch_under_electrode(board):
    """A hatched GND zone filling the bottom pour's hole under the electrode. It overlaps the
    solid pour by 0.3 mm, at a higher priority, so the two join."""
    z = gnd_zone(board, "B", "GND B hatch (electrode)", circle(ELECTRODE, ELECTRODE_UNDER + 0.3))
    z.SetAssignedPriority(1)  # wins where it overlaps the solid pour
    z.SetFillMode(pcbnew.ZONE_FILL_MODE_HATCH_PATTERN)
    z.SetHatchThickness(pcbnew.FromMM(ELECTRODE_HATCH[0]))
    z.SetHatchGap(pcbnew.FromMM(ELECTRODE_HATCH[1]))
    # Square to the board: the touch trace reaches the electrode at 45 degrees, so it crosses
    # the hatch lines instead of following one (AN4312 figure 31).
    z.SetHatchOrientation(pcbnew.EDA_ANGLE(0, pcbnew.DEGREES_T))


def edge_bands():
    """Strips EDGE_CLEARANCE wide inside the board outline, as keep-out polygons."""
    e = EDGE_CLEARANCE
    (cx, cy), r = END_ARC
    arc = [(cx + r * math.cos(math.pi * i / 32), cy + r * math.sin(math.pi * i / 32))
           for i in range(33)]
    inner = [(cx + (r - e) * math.cos(math.pi * i / 32), cy + (r - e) * math.sin(math.pi * i / 32))
             for i in range(33)]
    return [
        rect((93.5, 69.5), (94.0 + e, 82.0)), rect((106.0 - e, 69.5), (106.5, 82.0)),  # tongue
        rect((93.5, 69.5), (106.5, 70.0 + e)),                                        # tip
        rect((90.5, 81.5), (94.0, 82.0 + e)), rect((106.0, 81.5), (109.5, 82.0 + e)),  # shoulders
        rect((90.5, 81.5), (91.0 + e, cy)), rect((109.0 - e, 81.5), (109.5, cy)),       # sides
        arc + inner[::-1],                                                            # end
    ]


def is_routing(block):
    return block.startswith(("(segment", "(via", "(arc", "(zone"))


def obstacle(board):
    """Keep-outs where the GND tracks and vias will go, so Freerouting routes around them."""
    c = 0.2  # clearance
    for side, width, points in GND_TRACKS:
        r = width / 2 + c
        for (x0, y0), (x1, y1) in zip(points, points[1:]):
            d = math.hypot(x1 - x0, y1 - y0)
            nx, ny = -(y1 - y0) / d * r, (x1 - x0) / d * r  # normal
            ex, ey = (x1 - x0) / d * r, (y1 - y0) / d * r   # extension past the ends
            keepout(board, "GND track (routing only)", (side,),
                    [(x0 - ex + nx, y0 - ey + ny), (x1 + ex + nx, y1 + ey + ny),
                     (x1 + ex - nx, y1 + ey - ny), (x0 - ex - nx, y0 - ey - ny)],
                    tracks=True, vias=True)
    for at in GND_VIAS:
        keepout(board, "GND via (routing only)", ("F", "B"), circle(at, VIA[0] / 2 + c, 16),
                tracks=True, vias=True)


def keepouts(board):
    keepout(board, "tongue: no vias or pours", ("F", "B"), rect(*TONGUE), vias=True, pours=True)
    keepout(board, "tongue: nothing on the bottom", ("B",), rect(*TONGUE), tracks=True)
    # circle() is a 64-gon; widen it so its flat sides, not just its corners, keep the gap.
    keepout(board, "electrode: 4 mm gap, no vias or pours", ("F",),
            circle(ELECTRODE, ELECTRODE_GAP_TOP / math.cos(math.pi / 64)), vias=True, pours=True)
    keepout(board, "electrode: only the GND hatch underneath", ("B",),
            circle(ELECTRODE, ELECTRODE_UNDER), tracks=True, vias=True)
    for band in edge_bands():
        keepout(board, "board edge clearance", ("F", "B"), band, tracks=True, vias=True)


def autoroute(source, target):
    """Export source to Specctra DSN without the GND net, run Freerouting, import the session
    into target."""
    with tempfile.TemporaryDirectory() as tmp:
        dsn = pathlib.Path(tmp, "board.dsn")
        ses = pathlib.Path(tmp, "board.ses")
        assert pcbnew.ExportSpecctraDSN(source, str(dsn))
        text = dsn.read_text()
        text = re.sub(r"\(net GND\s*\(pins[^)]*\)\s*\)", "", text)
        text = re.sub(r"(?<=\s)GND(?=\s)", "", text)  # and from the net class lists
        dsn.write_text(text)
        subprocess.run([os.environ["FREEROUTING"], "--gui.enabled=false",
                        "--router.automatic_neckdown=false", "--router.neck_width_um=200",
                        "--router.autorouter.max_passes=100", "-de", str(dsn), "-do", str(ses)],
                       check=True, timeout=1800)
        assert pcbnew.ImportSpecctraSES(target, str(ses))


def drop_dangling_vias(board):
    """Remove vias that Freerouting left connected on one layer only."""
    pads = [p for fp in board.GetFootprints() for p in fp.Pads()]
    tracks = [t for t in board.GetTracks() if t.GetClass() != "PCB_VIA"]
    dropped = 0
    for v in [t for t in board.GetTracks() if t.GetClass() == "PCB_VIA"]:
        if v.GetNetname() == "GND":
            continue
        at, r = v.GetPosition(), v.GetWidth(pcbnew.F_Cu) // 2

        def joined(lay):
            for t in tracks:
                if t.GetLayer() == lay and t.GetNetCode() == v.GetNetCode() and \
                        min((t.GetStart() - at).EuclideanNorm(), (t.GetEnd() - at).EuclideanNorm()) <= r:
                    return True
            return any(p.GetNetCode() == v.GetNetCode() and p.IsOnLayer(lay) and p.HitTest(at)
                       for p in pads)

        if not (joined(pcbnew.F_Cu) and joined(pcbnew.B_Cu)):
            board.Remove(v)
            dropped += 1
    return dropped


def main():
    # Two copies of the placed, unrouted board: one with routing-only keep-outs for
    # Freerouting, one that receives the routes. (Items cannot be removed reliably through
    # the bindings, so the routing-only keep-outs never enter the saved board.)
    with tempfile.TemporaryDirectory() as tmp:
        bare = pathlib.Path(tmp, BOARD.name)
        bare.write_text(strip_blocks(BOARD.read_text(), is_routing))
        shutil.copy(BOARD.with_suffix(".kicad_pro"), tmp)  # the design rules live here
        source = pcbnew.LoadBoard(str(bare))
        board = pcbnew.LoadBoard(str(bare))

    keepouts(source)
    obstacle(source)
    for b in (source, board):
        for net, side, width, points in TRACKS:
            add_track(b, net, side, width, points)
        for net, at in VIAS:
            add_via(b, net, at)

    autoroute(source, board)  # the import keeps locked items and adds the routed ones
    print(f"dropped {drop_dangling_vias(board)} dangling vias")
    # Freerouting necks tracks down to 0.15 mm at some pins whatever its settings say;
    # the board's minimum is 0.2 mm (DRC checks the clearances this restores).
    for t in board.GetTracks():
        if t.GetClass() == "PCB_TRACK" and t.GetWidth() < pcbnew.FromMM(0.2):
            t.SetWidth(pcbnew.FromMM(0.2))

    keepouts(board)
    for side, width, points in GND_TRACKS:
        add_track(board, "GND", side, width, points)
    for at in GND_VIAS:
        add_via(board, "GND", at)
    gnd_pour(board, "F")
    gnd_pour(board, "B", hole=circle(ELECTRODE, ELECTRODE_UNDER))
    gnd_hatch_under_electrode(board)
    pcbnew.ZONE_FILLER(board).Fill(board.Zones())

    pcbnew.SaveBoard(str(BOARD), board)
    print(f"tracks and vias: {len(board.GetTracks())}")


main()
