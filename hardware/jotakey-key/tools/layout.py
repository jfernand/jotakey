"""First layout pass for the jotakey-key board, applied live to the board open in KiCad 10.

Draws the board outline (USB-A tongue + body with a rounded end) and places
every footprint. Runs through KiCad's IPC API (kicad-python), so KiCad must be running with
jotakey-key.kicad_pcb open; KiCad records each step for undo.

    pip install kicad-python   # in a virtualenv
    python layout.py

Coordinates are board millimetres (KiCad's y grows downwards). The tongue's leading edge is at
y = 70; the board extends towards +y.
"""
from kipy import KiCad
from kipy.board_types import BoardArc, BoardLayer, BoardSegment
from kipy.geometry import Angle, Vector2
from kipy.util.units import from_mm

EDGE_WIDTH = 0.05

# Outline: tongue x 94..106, y 70..82; body x 91..109 down to y 106.5, closed by a half circle
# of radius 9 around (100, 106.5). The touch electrode is concentric with that half circle.
OUTLINE = [((94, 70), (106, 70)), ((106, 70), (106, 82)), ((106, 82), (109, 82)),
           ((109, 82), (109, 106.5)), ((91, 106.5), (91, 82)), ((91, 82), (94, 82)),
           ((94, 82), (94, 70))]
END_ARC = ((109, 106.5), (100, 115.5), (91, 106.5))

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
    "E1": (100, 106.5, 0, "F"),
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


def v(x, y):
    return Vector2.from_xy_mm(x, y)


def edge(shape):
    shape.layer = BoardLayer.BL_Edge_Cuts
    shape.attributes.stroke.width = from_mm(EDGE_WIDTH)
    return shape


def main():
    board = KiCad().get_board()


    old_edges = [s for s in board.get_shapes() if s.layer == BoardLayer.BL_Edge_Cuts]
    if old_edges:
        board.remove_items(old_edges)

    shapes = []
    for (a, b) in OUTLINE:
        seg = BoardSegment()
        seg.start, seg.end = v(*a), v(*b)
        shapes.append(edge(seg))
    arc = BoardArc()
    arc.start, arc.mid, arc.end = (v(*p) for p in END_ARC)
    shapes.append(edge(arc))
    board.create_items(shapes)

    footprints = {f.reference_field.text.value: f for f in board.get_footprints()}
    to_flip = [footprints[r] for r, (*_, side) in PLACEMENT.items()
               if side == "B" and footprints[r].layer != BoardLayer.BL_B_Cu]
    if to_flip:
        board.flip_items(to_flip)
        footprints = {f.reference_field.text.value: f for f in board.get_footprints()}

    moved = []
    for ref, (x, y, rot, _side) in PLACEMENT.items():
        fp = footprints[ref]
        fp.position = v(x, y)
        fp.orientation = Angle.from_degrees(rot)
        moved.append(fp)
    board.update_items(moved)


    print(f"outline: {len(shapes)} shapes; placed {len(moved)} footprints, flipped {len(to_flip)}")


main()
