"""Board outline and footprint placement for the jotakey-key board.

Draws the board outline (USB-A tongue + body with a rounded end) and places every footprint,
in the saved jotakey-key.kicad_pcb, through KiCad's pcbnew bindings. Run it with KiCad's own
Python; then run route.py and silk.py, which build on the placement:

    <kicad>/AppRun python3.11 tools/layout.py

If the board is open in KiCad, save it first and revert it afterwards (File > Revert).

Coordinates are board millimetres (KiCad's y grows downwards). The tongue's leading edge is at
y = 70; the board extends towards +y.
"""
import pathlib

import pcbnew

from boardtext import strip_blocks

BOARD = pathlib.Path(__file__).resolve().parent.parent / "jotakey-key.kicad_pcb"
EDGE_WIDTH = 0.05

# Outline: tongue x 94..106, y 70..82; body x 91..109 down to y BODY_END, closed by a half
# circle of radius 9 around (100, BODY_END). The touch electrode is concentric with it. The
# body is long enough to keep 4 mm of bare board between the electrode and the copper above
# it (AN4312 3.5.6).
BODY_END = 108.0
OUTLINE = [((94, 70), (106, 70)), ((106, 70), (106, 82)), ((106, 82), (109, 82)),
           ((109, 82), (109, BODY_END)), ((91, BODY_END), (91, 82)), ((91, 82), (94, 82)),
           ((94, 82), (94, 70))]
END_ARC = ((109, BODY_END), (100, BODY_END + 9), (91, BODY_END))

# reference: (x, y, rotation in degrees, side)
PLACEMENT = {
    # USB-A contacts: leading edge on the tongue's edge.
    "J1": (100, 70, 0, "F"),
    # Power and protection, just behind the tongue.
    "U3": (95.5, 85.5, 90, "F"),     # LDO, VBUS pin towards the connector
    "C1": (92.6, 84.2, 90, "F"),     # LDO input
    "C2": (95.6, 88.4, 180, "F"),    # LDO output, under its 3V3 pin
    "C3": (92.6, 89.5, 90, "F"),     # 3V3 bulk
    "U4": (100.0, 85.0, 270, "F"),   # USB ESD on the board axis, connector side up, MCU side down
    # MCU in the middle: USB pins up, touch pins left, OPTIGA reset right.
    "U1": (100, 93.5, 90, "F"),
    # Under the MCU, each capacitor below its pin, GND pads away from the package.
    "C4": (97.8, 97.7, 270, "F"),    # VDD pin 1
    "C8": (99.75, 97.7, 270, "F"),   # NRST pin 4; its via to TP3 sits between C4 and C8
    "C6": (100.85, 97.7, 270, "F"),  # VDDA pin 5, 100 nF
    "C7": (101.95, 97.7, 270, "F"),  # VDDA pin 5, 1 uF
    # Left of the MCU, beside the pins they serve.
    "C10": (95.8, 92.2, 180, "F"),   # touch sampling capacitor, pin 27
    "R2": (95.8, 93.3, 0, "F"),      # touch series resistor, pin 28; electrode side left
    "R5": (95.8, 94.6, 180, "F"),    # BOOT0 pull-down, pin 31
    # Secure element in the top-right corner: SCL, RST and VCC face down towards the MCU,
    # SDA comes over the top. Pull-ups and decoupling on the way.
    "U2": (105.9, 86.4, 270, "F"),
    "R3": (103.0, 86.0, 270, "F"),   # SDA pull-up, on the SDA path left of U2
    "R4": (105.0, 90.6, 90, "F"),    # SCL pull-up, below the SCL path
    "C9": (107.9, 89.7, 270, "F"),   # OPTIGA VCC (pin 10)
    "C5": (103.7, 90.9, 270, "F"),   # MCU VDD pin 17, at the package corner
    # Touch electrode, concentric with the rounded end.
    "E1": (100, BODY_END, 0, "F"),
    # Status LED in the corner beside the electrode, visible from the top.
    "R1": (107.6, 96.9, 270, "F"),   # LED end up, towards U1 pin 9; D1 end down
    "D1": (107.6, 100.5, 90, "F"),
    # SWD pogo pads on the bottom side, 2.54 mm pitch, between the MCU and the electrode.
    "TP1": (94.92, 98.4, 0, "B"),
    "TP2": (97.46, 98.4, 0, "B"),
    "TP3": (100.00, 98.4, 0, "B"),
    "TP4": (102.54, 98.4, 0, "B"),
    "TP5": (105.08, 98.4, 0, "B"),
}


def mm(x, y):
    return pcbnew.VECTOR2I(pcbnew.FromMM(x), pcbnew.FromMM(y))


def edge(board, shape):
    shape.SetLayer(pcbnew.Edge_Cuts)
    shape.SetWidth(pcbnew.FromMM(EDGE_WIDTH))
    board.Add(shape)


def is_edge(block):
    return block.startswith(("(gr_line", "(gr_arc", "(gr_circle", "(gr_rect", "(gr_poly")) and \
        '(layer "Edge.Cuts")' in block


def main():
    BOARD.write_text(strip_blocks(BOARD.read_text(), is_edge))  # the old outline
    board = pcbnew.LoadBoard(str(BOARD))

    for a, b in OUTLINE:
        seg = pcbnew.PCB_SHAPE(board, pcbnew.SHAPE_T_SEGMENT)
        seg.SetStart(mm(*a))
        seg.SetEnd(mm(*b))
        edge(board, seg)
    arc = pcbnew.PCB_SHAPE(board, pcbnew.SHAPE_T_ARC)
    arc.SetArcGeometry(*(mm(*p) for p in END_ARC))
    edge(board, arc)

    flipped = 0
    for fp in board.GetFootprints():
        x, y, rot, side = PLACEMENT[fp.GetReference()]
        if (side == "B") != fp.IsFlipped():
            fp.Flip(fp.GetPosition(), pcbnew.FLIP_DIRECTION_TOP_BOTTOM)
            flipped += 1
        fp.SetPosition(mm(x, y))
        fp.SetOrientationDegrees(rot)

    pcbnew.SaveBoard(str(BOARD), board)
    print(f"outline: {len(OUTLINE) + 1} shapes; placed {len(PLACEMENT)} footprints, "
          f"flipped {flipped}")


main()
