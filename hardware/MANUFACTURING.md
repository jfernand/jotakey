# Jotakey key: manufacturing

How to order a hardware release from JLCPCB. The design is `jotakey-key/` at the release's
`hw-vX.Y.Z` tag; `HARDWARE.md` explains the choices behind it.

## 1. Build the package

From a checkout of the tag:

```sh
cd hardware/jotakey-key
KICAD_CLI="~/Applications/kicad-10.0.7-x86_64.AppImage kicad-cli" python3 tools/fab.py
```

`tools/fab.py` stops unless the schematic passes ERC and the board passes DRC (with schematic
parity and refilled zones). It writes `fab/hw-v<version>/` (not tracked by git):

| File | Upload as |
|---|---|
| `jotakey-key-hw-v<version>-gerbers.zip` | Gerber files (PCB order) |
| `jotakey-key-hw-v<version>-bom.csv` | BOM (assembly) |
| `jotakey-key-hw-v<version>-cpl.csv` | CPL / pick and place (assembly) |

Only the 20 parts with an LCSC number are assembled. The USB-A contacts (J1), the touch
electrode (E1) and the SWD pads (TP1–TP5) are copper on the board.

## 2. PCB options

| Option | Value | Why |
|---|---|---|
| Layers | 2 | |
| Thickness | **2.0 mm** | The edge connector must sit firmly in a USB-A receptacle |
| Solder mask | **Black** | Recorded in the board stackup |
| Silkscreen | White | |
| Surface finish | **ENIG** | Flat pads for the QFN; gold contacts |
| Gold fingers | **Yes, bevelled** (30°) | The USB-A contacts are the board edge |
| Via covering | Tented | The default; every via is 0.3 mm drill, 0.6 mm pad |
| Mark on PCB: order number | **Specify a location** | Printed where `JLCJLCJLCJLC` is, on the back |
| Mark on PCB: serial number | **Specify a location** | Printed in the solid 2 × 10 mm block on the back |
| Min track / clearance, min hole | 0.2 / 0.2 mm, 0.3 mm | Standard capability, no surcharge |

If the order form allows only one kind of mark, choose the serial number. Without "specify
a location", JLCPCB prints its marks wherever it finds room, possibly on the top.

## 3. Assembly options

- Top side only. All parts are JLCPCB stock; four are Extended (U1, U2, U4, C10), which adds a
  setup fee per part type.
- JLCPCB may require Standard (not Economic) assembly for a 2.0 mm board with gold fingers,
  and may add edge rails because parts sit within a few millimetres of the edge. Accept the
  rails it proposes, as long as none is on the USB-A tongue.
- Stock (JLCPCB, 2026-10-17): STM32L432KCU6 (C1337280) 57, OPTIGA SLS32AIA010MH (C539250) 60;
  every other part has thousands or more. Reserve U1 and U2 (pre-order) if the order is not
  placed straight away. If one runs out, source it through JLCPCB global sourcing or consign
  it, and record that here.

## 4. Check before paying

In JLCPCB's Gerber viewer:

- [ ] The outline: 47 mm long, 18 mm wide, 12 mm at the tongue; no other cut-outs.
- [ ] The four contacts reach the tongue's edge; VBUS and GND (outer) are longer.
- [ ] Bottom silkscreen reads `HW 0.1.0` (not `${HW_VERSION}`), and the SWD labels
      DIO, CLK, RST, 3V3, GND.
- [ ] Top silkscreen: the bolt on the touch pad, `jotakey`, and MCU, OPTIGA, LDO, ESD.

In the placement preview (rotations come straight from KiCad and may need a turn):

- [ ] U1 (STM32, QFN-32): pin 1 at the corner marked by the silkscreen triangle.
- [ ] U2 (OPTIGA, USON-10): pin 1 at the corner with the silkscreen triangle.
- [ ] U3 (LDO, SOT-23) and U4 (ESD, SOT-23-6): pin 1 at the silkscreen marker.
- [ ] D1 (LED): cathode towards the pad that connects to GND (the end away from R1).
- [ ] Capacitors and resistors on their pads.

If a part is turned, fix it in the preview for this order and add the correction to
`ROTATION_OFFSETS` in `tools/fab.py`, so the next build carries it.

## 5. First order

`HARDWARE.md` recommends checking the 2.0 mm edge connector in several USB ports before
committing to assembled boards. Either order five bare boards first, or order the first
assembled batch small (2–5) and test the fit on those.

## 6. Bring-up

Program and debug through the SWD pads with a pogo-pin jig (see `HARDWARE.md` §4); keep the
first units at readout protection level 0. Provisioning and locking (`AGENTS.md` §3a) come
after the firmware port.
