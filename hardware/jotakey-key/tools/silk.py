"""Silkscreen for the jotakey-key board, applied to the saved jotakey-key.kicad_pcb.

- Reference designators move to the fab layers. On an 18 mm board with 0402 parts they
  cannot sit next to their parts without covering pads; the assembly drawing (F.Fab) and the
  position file carry them instead.
- "HW <version>" on the bottom silkscreen, behind the touch electrode, and the title block.
  Both use the project text variable HW_VERSION (jotakey-key.kicad_pro, File > Project
  Settings > Text Variables), the one place the hardware version is set; KiCad substitutes it
  when it draws or plots the board.
- A solid 2 x 10 mm block on the bottom silkscreen marks where JLCPCB prints the board's
  serial number. Order with "Mark on PCB: Serial number, specify position"; without that
  option JLCPCB prints nothing there.
- "JLCJLCJLCJLC" along the opposite edge marks where JLCPCB prints its order number. Order
  with "Remove order number: specify a location"; otherwise it prints the number wherever it
  finds room.

Run it with KiCad's own Python, after route.py:

    <kicad>/AppRun python3.11 tools/silk.py
"""
import pathlib

import pcbnew

BOARD = pathlib.Path(__file__).resolve().parent.parent / "jotakey-key.kicad_pcb"

# Bottom side, along the left edge: clear of tracks, vias and the SWD pads, over the GND pour.
SERIAL_BLOCK = ((91.7, 85.0), (93.7, 95.0))
# Bottom side, along the other long edge, below the last via; JLCPCB's minimum is 0.8 mm.
ORDER_NUMBER_TEXT = ("JLCJLCJLCJLC", (107.6, 97.0), 0.8)  # text, position, height
# Bottom side, centred on the copper-free disc behind the touch electrode.
VERSION_TEXT = ("HW ${HW_VERSION}", (100.0, 108.0), 1.0)  # text, position, height

TITLE = "Jotakey key: STM32L432 + OPTIGA Trust M USB-A dongle"
DATE = "2026-10-17"  # of the HW_VERSION release
COMMENTS = ["Pin plan and parts: hardware/HARDWARE.md",
            "Fabrication and assembly: JLCPCB, 2 layers, 2.0 mm, ENIG"]


def mm(x, y):
    return pcbnew.VECTOR2I(pcbnew.FromMM(x), pcbnew.FromMM(y))


def main():
    board = pcbnew.LoadBoard(str(BOARD))

    for fp in board.GetFootprints():
        ref = fp.Reference()
        ref.SetLayer(pcbnew.B_Fab if fp.IsFlipped() else pcbnew.F_Fab)

    # Update a previous run's items in place: removing items through the bindings corrupts them.
    block = text = order = None
    for d in board.GetDrawings():
        if d.GetLayer() != pcbnew.B_SilkS:
            continue
        if d.GetClass() == "PCB_SHAPE" and d.GetShape() == pcbnew.SHAPE_T_RECTANGLE:
            block = d
        elif d.GetClass() == "PCB_TEXT" and d.GetText().startswith("HW "):
            text = d
        elif d.GetClass() == "PCB_TEXT" and d.GetText() == ORDER_NUMBER_TEXT[0]:
            order = d
    if block is None:
        block = pcbnew.PCB_SHAPE(board, pcbnew.SHAPE_T_RECTANGLE)
        board.Add(block)
    block.SetStart(mm(*SERIAL_BLOCK[0]))
    block.SetEnd(mm(*SERIAL_BLOCK[1]))
    block.SetLayer(pcbnew.B_SilkS)
    block.SetFilled(True)
    block.SetWidth(0)

    if text is None:
        text = pcbnew.PCB_TEXT(board)
        board.Add(text)
    label, at, height = VERSION_TEXT
    text.SetText(label)
    text.SetLayer(pcbnew.B_SilkS)
    text.SetPosition(mm(*at))
    text.SetTextSize(mm(height, height))
    text.SetTextThickness(pcbnew.FromMM(0.15))
    text.SetMirrored(True)

    if order is None:
        order = pcbnew.PCB_TEXT(board)
        board.Add(order)
    label, at, height = ORDER_NUMBER_TEXT
    order.SetText(label)
    order.SetLayer(pcbnew.B_SilkS)
    order.SetPosition(mm(*at))
    order.SetTextSize(mm(height, height))
    order.SetTextThickness(pcbnew.FromMM(0.15))
    order.SetTextAngleDegrees(90)
    order.SetMirrored(True)

    tb = board.GetTitleBlock()
    tb.SetTitle(TITLE)
    tb.SetRevision("${HW_VERSION}")
    tb.SetDate(DATE)
    tb.SetCompany("Jotakey")
    for i, c in enumerate(COMMENTS):
        tb.SetComment(i, c)

    pcbnew.SaveBoard(str(BOARD), board)


main()
