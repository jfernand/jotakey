"""Silkscreen for the jotakey-key board, applied to the saved jotakey-key.kicad_pcb.

- Reference designators move to the fab layers. On an 18 mm board with 0402 parts they
  cannot sit next to their parts without covering pads; the assembly drawing (F.Fab) and the
  position file carry them instead.
- A solid 2 x 10 mm block on the bottom silkscreen marks where JLCPCB prints the board's
  serial number. Order with "Mark on PCB: Serial number, specify position"; without that
  option JLCPCB prints nothing there.

Run it with KiCad's own Python, after route.py:

    <kicad>/AppRun python3.11 tools/silk.py
"""
import pathlib

import pcbnew

BOARD = pathlib.Path(__file__).resolve().parent.parent / "jotakey-key.kicad_pcb"

# Bottom side, along the left edge: clear of tracks, vias and the SWD pads, over the GND pour.
SERIAL_BLOCK = ((91.7, 85.0), (93.7, 95.0))


def mm(x, y):
    return pcbnew.VECTOR2I(pcbnew.FromMM(x), pcbnew.FromMM(y))


def main():
    board = pcbnew.LoadBoard(str(BOARD))

    for fp in board.GetFootprints():
        ref = fp.Reference()
        ref.SetLayer(pcbnew.B_Fab if fp.IsFlipped() else pcbnew.F_Fab)

    for d in list(board.GetDrawings()):
        if d.GetLayer() == pcbnew.B_SilkS and d.GetClass() == "PCB_SHAPE" and \
                d.GetShape() == pcbnew.SHAPE_T_RECTANGLE and d.IsFilled():
            board.Remove(d)  # a previous run's block
    block = pcbnew.PCB_SHAPE(board, pcbnew.SHAPE_T_RECTANGLE)
    block.SetStart(mm(*SERIAL_BLOCK[0]))
    block.SetEnd(mm(*SERIAL_BLOCK[1]))
    block.SetLayer(pcbnew.B_SilkS)
    block.SetFilled(True)
    block.SetWidth(0)
    board.Add(block)

    pcbnew.SaveBoard(str(BOARD), board)


main()
